# ScanVuln-Nmap-MetasploitNeste exemplo, o script começa definindo o host alvo e as portas a serem verificadas pelo Nmap. Em seguida, configura uma conexão com o Metasploit usando o msfrpc e define o objeto Nmap. O script executa a varredura do Nmap com os argumentos "-sV -O", que identificam a versão do software e tentam detectar o sistema operacional. Em seguida, o script itera sobre os resultados da varredura e busca exploits para os serviços identificados usando o Metasploit
