import socket
import threading
import argparse
import pyfiglet

WELL_KNOWN_PORTS = {
    20: "FTP Data Transfer",
    21: "FTP Command Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "Microsoft-DS",
    993: "IMAP over SSL",
    995: "POP3 over SSL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
}

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        print(f"\nErro: {message}")
        print(f"Tente usar -h ou --help para mais informações sobre como usar a aplicação.")
        self.exit(2)

    def print_help(self) -> None:
        print("Eduardo Vaz's Wonderful Port Scanner\n")
        print("Uso: python port_scanner.py -H <host> -s <porta-início> -e <porta-fim>\n")
        print("Exemplo: python port_scanner.py -H www.insper.edu.br -s 1 -e 1000\n")
        print("Opções:\n")
        print("  -H, --host        Host para fazer o scan (IP ou domínio) - obrigatório")
        print("  -s, --porta-inicio       Porta de início do intervalo - obrigatório")
        print("  -e, --porta-fim    Porta de fim do intervalo - opcional\n")



def scan_port(host, port):
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Erro: O host '{host}' não pôde ser resolvido.")
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = WELL_KNOWN_PORTS.get(port, "Serviço Desconhecido")
            print(f"Porta {port} está aberta em {host} ({ip}) - {service}")
        sock.close()
    except Exception as e:
        print(f"Erro escaneando porta {port} em {host}: {e}")

def scan_ports(host, start_port, end_port=None):
    if end_port is None: end_port = start_port
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(host, port))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    cybersec = pyfiglet.figlet_format("Cybersec") 
    port_scanner = pyfiglet.figlet_format("Port Scanner")
    print("\033[34m" + cybersec + "\033[0m\n" + "\033[33m" + port_scanner + "\033[0m")

    parser = CustomArgumentParser(description="Simple TCP Port Scanner")
    
    parser.add_argument("-H", "--host", required=True)
    parser.add_argument("-s", "--porta-inicio", type=int, required=True)
    parser.add_argument("-e", "--porta-fim", type=int, required=False)
    
    args = parser.parse_args()

    if args.porta_fim is not None:

        if args.porta_fim is not None and args.porta_inicio > args.porta_fim:
            parser.error("Porta de início deve ser menor ou igual à porta de fim.")

        print(f"Escaneando portas {args.porta_inicio}-{args.porta_fim} em {args.host}...")
    else:
        print(f"Escaneando porta {args.porta_inicio} em {args.host}...")
    scan_ports(args.host, args.porta_inicio, args.porta_fim)
