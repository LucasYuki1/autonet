"""
netconfig.py - Gerador interativo de configuracoes Cisco IOS.

Estrutura em secoes (separadas por '# ====') feita pra voce dividir em
modulos depois (ex: ipcalc.py, templates.py, cli.py) sem mexer na logica.

Como rodar:
    python netconfig.py
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Callable, Optional


# ============================================================
# 1. MODELOS DE DADOS
# ============================================================

@dataclass
class Subnet:
    network: IPv4Network
    name: str = ""
    vlan_id: Optional[int] = None
    vlan_name: str = ""
    hosts_needed: int = 0

    @property
    def gateway(self) -> IPv4Address:
        return next(self.network.hosts())

    @property
    def usable_hosts(self) -> int:
        return max(self.network.num_addresses - 2, 0)


@dataclass
class Interface:
    name: str
    ip: Optional[IPv4Address] = None
    mask: Optional[str] = None
    description: str = ""
    mode: str = "routed"  # "routed" | "access" | "trunk" | "subinterface"
    access_vlan: Optional[int] = None
    allowed_vlans: list[int] = field(default_factory=list)
    native_vlan: Optional[int] = None
    dot1q_vlan: Optional[int] = None  # so para mode == "subinterface"


@dataclass
class Device:
    hostname: str
    kind: str  # "router" ou "switch"
    domain: str = "lab.local"
    enable_password: str = ""
    console_password: str = ""
    aux_password: str = ""
    username: str = "admin"
    user_password: str = ""
    rsa_modulus: int = 2048
    banner: str = "Acesso restrito - somente pessoal autorizado."
    interfaces: list[Interface] = field(default_factory=list)
    vlans: list[Subnet] = field(default_factory=list)
    static_routes: list[tuple[str, str, str]] = field(default_factory=list)
    default_gateway: Optional[IPv4Address] = None
    # cada rota: (rede, mascara, next-hop)


@dataclass
class Project:
    base_block: Optional[IPv4Network] = None
    subnets: list[Subnet] = field(default_factory=list)
    devices: list[Device] = field(default_factory=list)


# ============================================================
# 2. CALCULO DE IP / SUB-REDES
# ============================================================

def equal_subnets(block: IPv4Network, n: int) -> list[IPv4Network]:
    """Divide um bloco em N sub-redes iguais (arredonda pra potencia de 2)."""
    new_prefix = block.prefixlen
    while (1 << (new_prefix - block.prefixlen)) < n:
        new_prefix += 1
        if new_prefix > 30:
            raise ValueError("Bloco insuficiente para tantas sub-redes.")
    return list(block.subnets(new_prefix=new_prefix))[:n]


def vlsm_subnets(block: IPv4Network, hosts_required: list[int]) -> list[IPv4Network]:
    """
    Aloca sub-redes via VLSM. Ordena por tamanho decrescente, aloca em
    sequencia e devolve na ordem original que o usuario informou.
    """
    order = sorted(enumerate(hosts_required), key=lambda x: -x[1])
    result: dict[int, IPv4Network] = {}
    pointer = int(block.network_address)
    end = int(block.broadcast_address)

    for original_index, hosts in order:
        needed = hosts + 2
        prefix = 32
        while (1 << (32 - prefix)) < needed:
            prefix -= 1
        if prefix < block.prefixlen:
            raise ValueError(f"{hosts} hosts nao cabem no bloco {block}.")
        size = 1 << (32 - prefix)
        if pointer % size != 0:
            pointer += size - (pointer % size)
        if pointer + size - 1 > end:
            raise ValueError(f"Bloco {block} esgotado ao alocar {hosts} hosts.")
        result[original_index] = IPv4Network(f"{IPv4Address(pointer)}/{prefix}")
        pointer += size

    return [result[i] for i in range(len(hosts_required))]


# ============================================================
# 3. TEMPLATES CISCO IOS
# ============================================================

def render_security(d: Device) -> list[str]:
    """
    Ordem do bloco de seguranca:
        enable
        configure terminal
        hostname
        enable secret           <- dentro do conf t, antes do domain-name
        ip domain-name
        crypto key generate rsa general-keys modulus
        username ... secret ...
        service password-encryption
        banner motd
        (se router) line con 0 / password / login
                    line aux 0 / password / login
    Apos isso adiciono line vty + ip ssh version 2 (necessario para o
    SSH realmente funcionar; o crypto key sozinho nao basta).
    """
    lines = [
        "enable",
        "configure terminal",
        f"hostname {d.hostname}",
    ]
    if d.enable_password:
        lines.append(f"enable secret {d.enable_password}")
    lines += [
        f"ip domain-name {d.domain}",
        f"crypto key generate rsa general-keys modulus {d.rsa_modulus}",
        f"username {d.username} secret {d.user_password}",
        "service password-encryption",
        f"banner motd #{d.banner}#",
    ]
    if d.kind == "router":
        lines += [
            "line con 0",
            f" password {d.console_password}",
            " login",
            " exit",
            "line aux 0",
            f" password {d.aux_password or d.console_password}",
            " login",
            " exit",
        ]
    # Habilita SSH propriamente
    lines += [
        "line vty 0 4",
        " transport input ssh",
        " login local",
        " exit",
        "ip ssh version 2",
    ]
    return lines


def render_vlans(d: Device) -> list[str]:
    out: list[str] = []
    for s in d.vlans:
        if s.vlan_id is None:
            continue
        out.append(f"vlan {s.vlan_id}")
        if s.vlan_name:
            out.append(f" name {s.vlan_name}")
        out.append(" exit")
    return out


def render_interfaces(d: Device) -> list[str]:
    out: list[str] = []
    for itf in d.interfaces:
        out.append(f"interface {itf.name}")
        if itf.description:
            out.append(f" description {itf.description}")
        if itf.mode == "access":
            out.append(" switchport mode access")
            if itf.access_vlan is not None:
                out.append(f" switchport access vlan {itf.access_vlan}")
        elif itf.mode == "trunk":
            out.append(" switchport mode trunk")
            if itf.allowed_vlans:
                vlans = ",".join(str(v) for v in itf.allowed_vlans)
                out.append(f" switchport trunk allowed vlan {vlans}")
            if itf.native_vlan is not None:
                out.append(f" switchport trunk native vlan {itf.native_vlan}")
        elif itf.mode == "subinterface":
            if itf.dot1q_vlan is not None:
                out.append(f" encapsulation dot1Q {itf.dot1q_vlan}")
            if itf.ip and itf.mask:
                out.append(f" ip address {itf.ip} {itf.mask}")
        else:
            # routed ou SVI (nome 'VlanN')
            if itf.ip and itf.mask:
                out.append(f" ip address {itf.ip} {itf.mask}")
        out.append(" no shutdown")
        out.append(" exit")
    return out


def render_routes(d: Device) -> list[str]:
    return [f"ip route {net} {mask} {nh}" for net, mask, nh in d.static_routes]


def render_device(d: Device) -> str:
    blocks = [
        f"! ===== {d.hostname} ({d.kind}) =====",
        *render_security(d),
        *render_vlans(d),
        *render_interfaces(d),
        *render_routes(d),
    ]
    if d.default_gateway:
        blocks.append(f"ip default-gateway {d.default_gateway}")
    blocks += [
        "end",
        "write memory",
    ]
    return "\n".join(blocks) + "\n"


# ============================================================
# 4. PERSISTENCIA
# ============================================================

def save_device(d: Device, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{d.hostname}.cfg"
    path.write_text(render_device(d), encoding="utf-8")
    return path


# ============================================================
# 5. CLI - HELPERS
# ============================================================

def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val or default


def ask_int(prompt: str, default: Optional[int] = None) -> int:
    while True:
        raw = ask(prompt, str(default) if default is not None else "")
        try:
            return int(raw)
        except ValueError:
            print("  -> valor invalido, tente de novo.")


def ask_yes(prompt: str, default: str = "s") -> bool:
    return ask(prompt + " (s/n)", default).lower().startswith("s")


# ============================================================
# 6. CLI - PASSOS
# ============================================================

def step_block(p: Project) -> None:
    print("\n[1] Bloco de IP base")
    raw = ask("Bloco (ex: 192.168.0.0/24)", "192.168.0.0/24")
    p.base_block = IPv4Network(raw, strict=False)
    print(f"  OK  bloco={p.base_block}  total={p.base_block.num_addresses} enderecos")


def step_subnets(p: Project) -> None:
    print("\n[2] Sub-redes (opcional)")
    if p.base_block is None:
        print("  -> defina o bloco primeiro.")
        return
    mode = ask("Modo: (e)quals / (v)lsm / (s)kip", "e").lower()
    if mode.startswith("s"):
        return
    p.subnets.clear()
    n = ask_int("Quantas sub-redes?", 4)
    if mode.startswith("v"):
        hosts = [ask_int(f"  Hosts na sub-rede {i+1}", 30) for i in range(n)]
        nets = vlsm_subnets(p.base_block, hosts)
        for i, net in enumerate(nets):
            p.subnets.append(Subnet(network=net, name=f"NET{i+1}", hosts_needed=hosts[i]))
    else:
        nets = equal_subnets(p.base_block, n)
        for i, net in enumerate(nets):
            p.subnets.append(Subnet(network=net, name=f"NET{i+1}"))
    for s in p.subnets:
        print(f"  OK  {s.name}: {s.network}  gw={s.gateway}  hosts uteis={s.usable_hosts}")


def step_vlans(p: Project) -> None:
    print("\n[3] VLANs")
    if not p.subnets:
        print("  -> defina sub-redes primeiro.")
        return
    for s in p.subnets:
        raw = ask(f"VLAN ID para {s.name} ({s.network}) [enter pula]")
        if not raw:
            continue
        s.vlan_id = int(raw)
        s.vlan_name = ask(f"  Nome da VLAN {s.vlan_id}", f"VLAN{s.vlan_id}")


def _pick_subnet(p: Project) -> Optional[Subnet]:
    if not p.subnets:
        return None
    print("    Sub-redes:")
    for idx, s in enumerate(p.subnets):
        vlan = f" VLAN{s.vlan_id}" if s.vlan_id else ""
        print(f"      [{idx}] {s.name} {s.network}{vlan}")
    pick = ask("    Indice (enter = manual)")
    if pick.isdigit() and 0 <= int(pick) < len(p.subnets):
        return p.subnets[int(pick)]
    return None


def _list_vlans_avail(p: Project) -> list[Subnet]:
    return [s for s in p.subnets if s.vlan_id is not None]


def _configure_access(name: str, p: Project) -> Interface:
    itf = Interface(name=name, mode="access")
    vlans_avail = _list_vlans_avail(p)
    if vlans_avail:
        print("    VLANs disponiveis:")
        for s in vlans_avail:
            print(f"      {s.vlan_id}  {s.vlan_name}  ({s.network})")
    raw = ask("    VLAN de acesso (ID)")
    if raw.isdigit():
        itf.access_vlan = int(raw)
        itf.description = f"Access VLAN {itf.access_vlan}"
    return itf


def _configure_trunk(name: str, p: Project) -> Interface:
    itf = Interface(name=name, mode="trunk")
    vlans_avail = _list_vlans_avail(p)
    default = ",".join(str(s.vlan_id) for s in vlans_avail) if vlans_avail else "all"
    raw = ask("    VLANs permitidas (ex: 10,20,30 ou 'all')", default)
    if raw and raw.lower() != "all":
        itf.allowed_vlans = [int(x) for x in raw.split(",") if x.strip().isdigit()]
    native = ask("    VLAN nativa (enter pula)")
    if native.isdigit():
        itf.native_vlan = int(native)
    itf.description = "Trunk port"
    return itf


def _configure_routed(name: str, p: Project) -> Interface:
    s = _pick_subnet(p)
    if s is not None:
        ip = ask("    IP (enter = gateway)", str(s.gateway))
        desc = s.name + (f" VLAN{s.vlan_id}" if s.vlan_id else "")
        return Interface(
            name=name,
            ip=IPv4Address(ip),
            mask=str(s.network.netmask),
            description=desc,
            mode="routed",
        )
    ip = ask("    IP")
    mask = ask("    Mascara (ex: 255.255.255.0)")
    return Interface(
        name=name,
        ip=IPv4Address(ip) if ip else None,
        mask=mask or None,
        mode="routed",
    )


def _configure_subinterfaces(name: str, p: Project) -> list[Interface]:
    """
    Router-on-a-stick: interface fisica sem IP + uma subinterface
    por VLAN com encapsulation dot1Q.
    """
    parent = Interface(name=name, mode="routed", description="Trunk router-on-a-stick")
    result: list[Interface] = [parent]
    vlans_avail = _list_vlans_avail(p)
    if vlans_avail:
        print("    VLANs com sub-rede definida:")
        for s in vlans_avail:
            print(f"      VLAN {s.vlan_id}  {s.vlan_name}  ({s.network})")
    print("    Informe as subinterfaces (VLAN ID vazia termina).")
    while True:
        vid_raw = ask("    VLAN ID da subinterface")
        if not vid_raw.isdigit():
            break
        vid = int(vid_raw)
        sub = Interface(name=f"{name}.{vid}", mode="subinterface", dot1q_vlan=vid)
        match = next((s for s in vlans_avail if s.vlan_id == vid), None)
        if match:
            ip = ask("    IP (enter = gateway)", str(match.gateway))
            sub.ip = IPv4Address(ip)
            sub.mask = str(match.network.netmask)
            sub.description = f"VLAN {vid} {match.vlan_name}"
        else:
            ip = ask("    IP")
            mask = ask("    Mascara")
            if ip and mask:
                sub.ip = IPv4Address(ip)
                sub.mask = mask
            sub.description = f"VLAN {vid}"
        result.append(sub)
        print(f"    OK  {sub.name} adicionada.")
    return result


def _configure_physical(p: Project, kind: str, idx: int) -> list[Interface]:
    name = ask(f"    [{idx}] Nome (ex: GigabitEthernet0/0, FastEthernet0/1)")
    if not name:
        return []
    if kind == "switch":
        mode = ask("    Modo: (a)ccess / (t)runk / (r)outed", "a").lower()
    else:
        mode = ask(
            "    Modo: (r)outed / (s)ubinterfaces dot1Q (router-on-a-stick)", "r"
        ).lower()
    if mode.startswith("a"):
        return [_configure_access(name, p)]
    if mode.startswith("t"):
        return [_configure_trunk(name, p)]
    if mode.startswith("s") and kind == "router":
        return _configure_subinterfaces(name, p)
    return [_configure_routed(name, p)]


def _configure_svi(p: Project) -> Optional[Interface]:
    vlans_avail = _list_vlans_avail(p)
    if vlans_avail:
        print("    VLANs com sub-rede definida:")
        for idx, s in enumerate(vlans_avail):
            print(f"      [{idx}] VLAN {s.vlan_id} {s.vlan_name}  {s.network}")
        pick = ask("    Indice (enter = manual)")
        if pick.isdigit() and 0 <= int(pick) < len(vlans_avail):
            s = vlans_avail[int(pick)]
            ip = ask("    IP (enter = gateway)", str(s.gateway))
            return Interface(
                name=f"Vlan{s.vlan_id}",
                ip=IPv4Address(ip),
                mask=str(s.network.netmask),
                description=f"SVI {s.name}",
                mode="routed",
            )
    vid_raw = ask("    VLAN ID")
    if not vid_raw.isdigit():
        return None
    ip_raw = ask("    IP")
    mask = ask("    Mascara")
    if not ip_raw or not mask:
        return None
    return Interface(
        name=f"Vlan{vid_raw}",
        ip=IPv4Address(ip_raw),
        mask=mask,
        description=f"SVI VLAN {vid_raw}",
        mode="routed",
    )


def step_devices(p: Project) -> None:
    print("\n[4] Dispositivos")
    while ask_yes("Adicionar dispositivo?", "s"):
        hostname = ask("  Hostname (ex: R1, SW1)")
        if not hostname:
            print("  -> hostname obrigatorio.")
            continue
        kind = ask("  Tipo (router/switch)", "router").lower()
        d = Device(hostname=hostname, kind=kind)

        n_itf = ask_int("  Quantas interfaces fisicas?", 1)
        for i in range(n_itf):
            d.interfaces.extend(_configure_physical(p, d.kind, i + 1))

        if d.kind == "switch":
            if _list_vlans_avail(p) and ask_yes("  Anexar VLANs definidas ao switch?", "s"):
                d.vlans = _list_vlans_avail(p)
            if ask_yes("  Adicionar SVI(s) (interface VlanN com IP)?", "n"):
                while True:
                    svi = _configure_svi(p)
                    if svi:
                        d.interfaces.append(svi)
                        print(f"    OK  {svi.name} adicionada.")
                    if not ask_yes("    Mais uma SVI?", "n"):
                        break
            if ask_yes("  Definir default-gateway (switch L2)?", "n"):
                gw = ask("    Default gateway")
                if gw:
                    d.default_gateway = IPv4Address(gw)

        if d.kind == "router" and ask_yes("  Adicionar rotas estaticas?", "n"):
            while True:
                net = ask("      Rede destino (ex: 10.0.0.0)")
                mask = ask("      Mascara (ex: 255.255.255.0)")
                nh = ask("      Next-hop (IP)")
                if net and mask and nh:
                    d.static_routes.append((net, mask, nh))
                if not ask_yes("      Mais uma rota?", "n"):
                    break

        p.devices.append(d)
        print(f"  OK  {d.hostname} adicionado.")


def step_security(p: Project) -> None:
    print("\n[5] Seguranca / SSH")
    if not p.devices:
        print("  -> cadastre dispositivos primeiro.")
        return
    if ask_yes("Aplicar a mesma config a todos?", "s"):
        domain = ask("Dominio", "lab.local")
        modulus = ask_int("Tamanho da chave RSA (modulus)", 2048)
        username = ask("Username", "admin")
        upw = ask("Senha do usuario")
        epw = ask("Enable secret")
        cpw = ask("Senha do console (line con 0)", upw)
        aux = ask("Senha line aux 0 (so afeta routers)", cpw)
        banner = ask("Banner motd", "Acesso restrito - somente pessoal autorizado.")
        for d in p.devices:
            d.domain = domain
            d.rsa_modulus = modulus
            d.username = username
            d.user_password = upw
            d.enable_password = epw
            d.console_password = cpw
            d.aux_password = aux
            d.banner = banner
    else:
        for d in p.devices:
            print(f"  -- {d.hostname} --")
            d.domain = ask("  Dominio", "lab.local")
            d.rsa_modulus = ask_int("  Modulus RSA", 2048)
            d.username = ask("  Username", "admin")
            d.user_password = ask("  Senha do usuario")
            d.enable_password = ask("  Enable secret")
            d.console_password = ask("  Senha console", d.user_password)
            if d.kind == "router":
                d.aux_password = ask("  Senha line aux", d.console_password)
            d.banner = ask("  Banner motd", "Acesso restrito.")


def step_export(p: Project) -> None:
    print("\n[6] Exportar .cfg")
    if not p.devices:
        print("  -> nada para exportar.")
        return
    out_dir = Path(ask("Diretorio de saida", "configs"))
    for d in p.devices:
        path = save_device(d, out_dir)
        print(f"  OK  {path.resolve()}")


def step_show(p: Project) -> None:
    print("\n--- Estado do projeto ---")
    print(f"Bloco base : {p.base_block}")
    print(f"Sub-redes  : {len(p.subnets)}")
    for s in p.subnets:
        vlan = f"  VLAN {s.vlan_id} ({s.vlan_name})" if s.vlan_id else ""
        print(f"  - {s.name}: {s.network}  gw={s.gateway}{vlan}")
    print(f"Dispositivos: {len(p.devices)}")
    for d in p.devices:
        print(f"  - {d.hostname} ({d.kind})  {len(d.interfaces)} intf"
              f"  {len(d.static_routes)} rotas")


def step_preview(p: Project) -> None:
    print("\n--- Preview das configs ---")
    if not p.devices:
        print("  (nenhum dispositivo)")
        return
    for d in p.devices:
        print(render_device(d))


# ============================================================
# 7. MENU
# ============================================================

MENU = """
============== netconfig ==============
 1) Bloco de IP base
 2) Sub-redes (equals / VLSM)
 3) VLANs
 4) Dispositivos
 5) Seguranca / SSH
 6) Exportar .cfg
 7) Mostrar estado
 8) Preview no terminal
 0) Sair
=======================================
"""


def main() -> None:
    p = Project()
    actions: dict[str, Callable[[Project], None]] = {
        "1": step_block,
        "2": step_subnets,
        "3": step_vlans,
        "4": step_devices,
        "5": step_security,
        "6": step_export,
        "7": step_show,
        "8": step_preview,
    }
    while True:
        print(MENU)
        choice = input("Escolha: ").strip()
        if choice == "0":
            print("Ate mais!")
            return
        fn = actions.get(choice)
        if not fn:
            print("Opcao invalida.")
            continue
        try:
            fn(p)
        except Exception as e:
            print(f"ERRO: {e}")


if __name__ == "__main__":
    main()
