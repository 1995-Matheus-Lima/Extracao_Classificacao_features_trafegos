from subprocess import run, PIPE
import json
import csv
import math


# Variáveis globais
tempo_inicial = '10:47:35'
tempo_final = '10:47:36'
CSV = 'Captura52_Infected.csv'


# Função para atualizar intervalo de captura
def atualiza_hora():
    global tempo_inicial
    global tempo_final
    tempo_inicial = tempo_final
    h, m, s = map(int, tempo_final.split(':'))
    
    s += 1
    if s == 60:
        s = 0
        m += 1
        if m == 60:
            m = 0
            h += 1
            if h == 24:
                h = 0

    tempo_final = f'{h:02d}:{m:02d}:{s:02d}'


#Função que executa comandos no prompt
def geraPcap(tempoInicial, tempoFinal, arqEntrada, arqSaida):
    comando = ['editcap', '-A', f'2011-08-18 {tempoInicial}', '-B', f'2011-08-18 {tempoFinal}', arqEntrada, arqSaida]
    run(comando)
# fim da Função que executa comandos no prompt

# Gerar o arquivo com o o intervalo de tempo definido que caracteriza o tráfego (normal, normal+malicioso+antesDoAtaque, Normal+malicioso+durante_ataque)
geraPcap(tempo_inicial, "10:52:35", "capture20110818-2.truncated.pcap", "saidaPrincIpal.pcap")


#Criar CSV
Headers = ['Frame_len', 'Frame_cap_len', 'Frame_marked', 'Frame_ignored', 'Qtd_total_de_Ip', 'Ip_hdr_len', 'Ip_len', 'Ip_ttl', 'Ip_src', 'Ip_dst','Ip_flags_rb','Ip_flags_df','Ip_flags_mf', 'Qtd_total_de_Tcp', 'Tcp_stream','Tcp_completeness', 'Tcp_len', 'Tcp_ack', 'Tcp_hdr_len', 'Tcp_flags_res', 'Tcp_flags_ns', 'Tcp_flags_cwr', 'Tcp_flags_ecn', 'Tcp_flags_urg', 'Tcp_flags_ack', 'Tcp_flags_push', 'Tcp_flags_reset', 'Tcp_flags_syn', 'Tcp_flags_fin', 'Tcp_window_size_value', 'Tcp_window_size_scalefactor', 'Tcp_urgent_pointer', 'Tcp_time_relative', 'Tcp_time_delta', 'Tcp_analysis_bytes_in_flight', 'Tcp_analysis_push_bytes_sent', 'Qtd_total_de_Udp', 'Qtd_total_de_Icmp', 'Icmp_ip_hdr_len', 'Icmp_ip_len', 'Icmp_ip_ttl', 'Icmp_ip_dsfield_dscp','Icmp_ip_dsfield_ecn','Has_bot','Qtd_total_de_Pacotes']

# 'Entropy_src_normalized', 'Entropy_dst_normalized',
with open(CSV, mode='w', newline='') as arquivo_csv:
    escritor_csv = csv.writer(arquivo_csv)
    escritor_csv.writerow(Headers)

while tempo_inicial != '10:52:35':  
    # "Quebrar" em intervalos de 1 segundo
    geraPcap(tempo_inicial, tempo_final, "saidaPrincIpal.pcap", "saida.pcap")

    # Função para Gerar Json
    def geraJson(entrada):
        comando = ['tshark', '-r', entrada, '-T', 'json']
        with open('arq.json', 'w') as arquivo_json:
            run(comando, stdout=arquivo_json)
    # Fim da Função para Gerar Json
    geraJson('saida.pcap')

    #Lendo arquivo json 
    #arq = open("arq.json")
    # linhas = arq.readlines()
    # for linha in linhas:
    #     print(linha)




    #Abrir json
    with open("arq.json",'r') as arquivo: 
        obj = json.load(arquivo)


    #Features
    Frame_len = 0.0
    Frame_cap_len = 0.0
    Frame_marked = 0.0 
    Frame_ignored = 0.0

    Ip = 0.0
    Ip_hdr_len = 0.0
    Ip_len = 0.0
    Ip_ttl = 0.0
    Ip_src = 0.0
    Ip_dst = 0.0
    Ip_flags_rb = 0.0
    Ip_flags_df = 0.0
    Ip_flags_mf = 0.0


    Tcp = 0.0
    Tcp_stream = 0.0
    Tcp_len = 0.0
    Tcp_completeness = 0.0
    Tcp_ack = 0.0
    Tcp_hdr_len = 0.0
    Tcp_flags_res = 0.0
    Tcp_flags_ns = 0.0
    Tcp_flags_cwr = 0.0
    Tcp_flags_ecn = 0.0
    Tcp_flags_urg = 0.0
    Tcp_flags_ack = 0.0
    Tcp_flags_push = 0.0
    Tcp_flags_reset = 0.0
    Tcp_flags_syn = 0.0
    Tcp_flags_fin = 0.0
    Tcp_window_size_value = 0.0
    Tcp_window_size_scalefactor = 0.0
    Tcp_urgent_pointer = 0.0
    Tcp_time_relative = 0.0
    Tcp_time_delta = 0.0
    Tcp_analysis_bytes_in_flight = 0.0
    Tcp_analysis_push_bytes_sent = 0.0

    Udp = 0.0 

    Icmp = 0.0 
    Icmp_ip_hdr_len = 0.0 
    Icmp_ip_len = 0.0 
    Icmp_ip_ttl = 0.0
    Icmp_ip_dsfield_dscp = 0.0
    Icmp_ip_dsfield_ecn = 0.0

    Has_bot = 0.0

    size = len(obj)

    dict_dst = {}
    dict_src = {}
    # Contar Protocolos e atribuir valores
    i = 0
    while i < size:
        if "_source" in obj[i] and "layers" in obj[i]["_source"]:
            #Aninhados com FRAME 
            if "frame" in obj[i]["_source"]["layers"]:
                Frame_diretorio = obj[i]["_source"]["layers"]["frame"];
                if 'frame.len' in Frame_diretorio:
                    Frame_len += float(Frame_diretorio['frame.len'])
                if 'frame.cap_len' in Frame_diretorio:
                    Frame_cap_len += float(Frame_diretorio['frame.cap_len'])
                if 'frame.marked' in Frame_diretorio:
                    Frame_marked += float(Frame_diretorio['frame.marked'])
                if 'frame.ignored' in Frame_diretorio:
                    Frame_ignored += float(Frame_diretorio['frame.ignored'])
            #Aninhados com Protocolo IP
            if "ip" in obj[i]["_source"]["layers"]:
                Ip +=1
                Ip_diretorio = obj[i]["_source"]["layers"]['ip']
                if 'ip.hdr_len' in Ip_diretorio:
                    Ip_hdr_len += float(Ip_diretorio['ip.hdr_len'])
                if 'ip.len' in Ip_diretorio:
                    Ip_len += float(Ip_diretorio['ip.len'])
                if 'ip.ttl' in Ip_diretorio:
                    Ip_ttl += float(Ip_diretorio['ip.ttl'])
                if 'ip.src' in Ip_diretorio:
                    Ip_src += 1
                    #Checar se tem bot
                    if Ip_diretorio['ip.src'] in ['147.32.84.165','147.32.84.191','147.32.84.192']:
                        Has_bot = 1
                if 'ip.dst' in Ip_diretorio:
                    Ip_dst += 1
                if 'ip.flags_tree' in Ip_diretorio:
                    if 'ip.flags.rb' in Ip_diretorio['ip.flags_tree']:
                        Ip_flags_rb += float(Ip_diretorio['ip.flags_tree']['ip.flags.rb'])
                    if 'ip.flags.df' in Ip_diretorio['ip.flags_tree']:
                        Ip_flags_df += float(Ip_diretorio['ip.flags_tree']['ip.flags.df'])
                    if 'ip.flags.mf' in Ip_diretorio['ip.flags_tree']:
                        Ip_flags_mf += float(Ip_diretorio['ip.flags_tree']['ip.flags.mf'])

            #Aninhados com Protocolo ICMP
            
            if "icmp" in obj[i]["_source"]["layers"]:
                Icmp_diretorio = obj[i]["_source"]["layers"]["icmp"]
                if "ip" in Icmp_diretorio:
                    if "ip.hdr_len" in Icmp_diretorio["ip"]:
                        Icmp_ip_hdr_len += float(Icmp_diretorio['ip']['ip.hdr_len'])
                    if "ip.len" in Icmp_diretorio['ip']:
                        Icmp_ip_len += float(Icmp_diretorio['ip']['ip.len'])
                    if "ip.ttl" in Icmp_diretorio['ip']:
                        Icmp_ip_ttl += float(Icmp_diretorio['ip']['ip.ttl'])
                    if "ip.flags_tree" in Icmp_diretorio['ip']:
                        if "ip.dsfield.dscp" in Icmp_diretorio['ip']["ip.flags_tree"]:
                            Icmp_ip_dsfield_dscp += float(Icmp_diretorio['ip']["ip.flags_tree"])
                        if "ip.dsfield.ecn" in Icmp_diretorio['ip']["ip.flags_tree"]:
                            Icmp_ip_dsfield_ecn += float(Icmp_diretorio['ip']["ip.flags_tree"])
                if "udp" in Icmp_diretorio:
                    Udp += 1
                Icmp += 1
            #Aninhados com Protocolo TCP
            if "tcp" in obj[i]["_source"]["layers"]:
                Tcp += 1
                tcp_diretorio = obj[i]["_source"]["layers"]["tcp"]
                if "tcp.srcport" in tcp_diretorio:
                    if tcp_diretorio["tcp.srcport"] in dict_src:
                        dict_src[tcp_diretorio["tcp.srcport"]] += 1
                    else:
                        dict_src[tcp_diretorio["tcp.srcport"]] = 1
                if "tcp.dstport" in tcp_diretorio:
                    if tcp_diretorio["tcp.dstport"] in dict_dst:
                        dict_dst[tcp_diretorio["tcp.dstport"]] += 1
                    else:
                        dict_dst[tcp_diretorio["tcp.dstport"]] = 1
                if "tcp.stream" in tcp_diretorio:
                    Tcp_stream += float(tcp_diretorio["tcp.stream"])
                if "tcp.len" in tcp_diretorio:
                    Tcp_len += float(tcp_diretorio["tcp.len"])
                if "tcp.completeness" in tcp_diretorio:
                    Tcp_completeness += float(tcp_diretorio["tcp.completeness"])
                if "tcp.ack" in tcp_diretorio:
                    Tcp_ack += float(tcp_diretorio["tcp.ack"])
                if "tcp.hdr_len" in tcp_diretorio:
                    Tcp_hdr_len += float(tcp_diretorio["tcp.hdr_len"])
                if "tcp.flags_tree" in tcp_diretorio:
                    if "tcp.flags.res" in tcp_diretorio["tcp.flags_tree"]:
                        Tcp_flags_res += float(tcp_diretorio["tcp.flags_tree"]["tcp.flags.res"])
                    if "tcp.flags.ns" in tcp_diretorio["tcp.flags_tree"]:
                        Tcp_flags_ns += float(tcp_diretorio["tcp.flags_tree"]["tcp.flags.ns"])
                    if "tcp.flags.cwr" in tcp_diretorio["tcp.flags_tree"]:
                        Tcp_flags_cwr += float(tcp_diretorio["tcp.flags_tree"]["tcp.flags.cwr"])
                    if "tcp.flags.ecn" in tcp_diretorio["tcp.flags_tree"]:
                        Tcp_flags_ecn += float(tcp_diretorio["tcp.flags_tree"]["tcp.flags.ecn"])
                    if "tcp.flags.urg" in tcp_diretorio["tcp.flags_tree"]:
                        Tcp_flags_urg += float(tcp_diretorio["tcp.flags_tree"]["tcp.flags.urg"])
                    if "tcp.flags.ack" in tcp_diretorio["tcp.flags_tree"]:
                        Tcp_flags_ack += float(tcp_diretorio["tcp.flags_tree"]["tcp.flags.ack"])
                    if "tcp.flags.push" in tcp_diretorio["tcp.flags_tree"]:
                        Tcp_flags_push += float(tcp_diretorio["tcp.flags_tree"]["tcp.flags.push"])
                    if "tcp.flags.reset" in tcp_diretorio["tcp.flags_tree"]:
                        Tcp_flags_reset += float(tcp_diretorio["tcp.flags_tree"]["tcp.flags.reset"])
                    if "tcp.flags.syn" in tcp_diretorio["tcp.flags_tree"]:
                        Tcp_flags_syn += float(tcp_diretorio["tcp.flags_tree"]["tcp.flags.syn"])
                    if "tcp.flags.fin" in tcp_diretorio["tcp.flags_tree"]:
                        Tcp_flags_fin += float(tcp_diretorio["tcp.flags_tree"]["tcp.flags.fin"])
                if "tcp.window_size_value" in tcp_diretorio:
                    Tcp_window_size_value += float(tcp_diretorio["tcp.window_size_value"])  
                if "tcp.window_size_scalefactor" in tcp_diretorio:
                    Tcp_window_size_scalefactor += float(tcp_diretorio["tcp.window_size_scalefactor"])  
                if "tcp.urgent_pointer" in tcp_diretorio:
                    Tcp_urgent_pointer += float(tcp_diretorio["tcp.urgent_pointer"])  
                if "Timestamps" in tcp_diretorio:
                    if "Tcp_time_relative" in tcp_diretorio["Timestamps"]:
                        Tcp_time_relative += float(tcp_diretorio["Timestamps"]['tcp.time_relative'])  
                    if "Tcp_time_delta" in tcp_diretorio["Timestamps"]:
                        Tcp_time_delta += float(tcp_diretorio["Timestamps"]['tcp.time_delta'])  
                if "tcp.analysis" in tcp_diretorio:
                    if "tcp.analysis.bytes_in_flight" in tcp_diretorio["tcp.analysis"]:
                        Tcp_analysis_bytes_in_flight += float(tcp_diretorio["tcp.analysis"]['tcp.analysis.bytes_in_flight'])  
                    if "tcp.analysis.push_bytes_sent" in tcp_diretorio["tcp.analysis"]:
                        Tcp_analysis_push_bytes_sent += float(tcp_diretorio["tcp.analysis"]['tcp.analysis.push_bytes_sent'])  
                
            #Aninhados com Protocolo UDP
            if "udp" in obj[i]["_source"]["layers"]:
                Udp += 1
                udp_diretorio = obj[i]["_source"]["layers"]["udp"]
                if "udp.srcport" in udp_diretorio:
                    if udp_diretorio["udp.srcport"] in dict_src:
                        dict_src[udp_diretorio["udp.srcport"]] += 1
                    else:
                        dict_src[udp_diretorio["udp.srcport"]] = 1
                if "udp.dstport" in udp_diretorio:
                    if udp_diretorio["udp.dstport"] in dict_dst:
                        dict_dst[udp_diretorio["udp.dstport"]] += 1
                    else:
                        dict_dst[udp_diretorio["udp.dstport"]] = 1
        i+= 1



    # #Somar valores no dict de origem/Destino
    # Sum_src = 0
    # Sum_dst = 0
    # for valor in dict_src.values():
    #     Sum_src += valor
    # for valor in dict_dst.values():
    #     Sum_dst += valor

    # #Calculo da entropia Entropia
    # max_entropy_src = math.log2(len(dict_src))
    # max_entropy_dst = math.log2(len(dict_dst))

    # #Entropia Normalizada
    # Entropy_src = 0
    # for valor in dict_src.values():
    #     x = (valor/Sum_src) * math.log2(valor/Sum_src)
    #     Entropy_src += x
    # for valor in dict_src.values():
    #     x = (valor/Sum_src) * math.log2(valor/Sum_src)
    # if max_entropy_src != 0:
    #     Entropy_src_normalized = (-1)* Entropy_src / max_entropy_src
    # else:
    #     Entropy_src_normalized = (-1)* Entropy_src
    # Entropy_dst = 0
    # for valor in dict_dst.values():
    #     x = (valor/Sum_dst) * math.log2(valor/Sum_dst)
    #     Entropy_dst += x
    # for valor in dict_dst.values():
    #     x = (valor/Sum_dst) * math.log2(valor/Sum_dst)
    # if max_entropy_dst != 0:
    #     Entropy_dst_normalized = (-1)* Entropy_dst / max_entropy_dst
    # else:
    #     Entropy_dst_normalized = (-1)* Entropy_dst


    array = [
        Frame_len, Frame_cap_len, Frame_marked, Frame_ignored, Ip, Ip_hdr_len, Ip_len, Ip_ttl, Ip_src, Ip_dst,
        Ip_flags_rb, Ip_flags_df, Ip_flags_mf, Tcp, Tcp_stream, Tcp_completeness, Tcp_len, Tcp_ack, Tcp_hdr_len,
        Tcp_flags_res, Tcp_flags_ns, Tcp_flags_cwr, Tcp_flags_ecn, Tcp_flags_urg, Tcp_flags_ack, Tcp_flags_push,
        Tcp_flags_reset, Tcp_flags_syn, Tcp_flags_fin, Tcp_window_size_value, Tcp_window_size_scalefactor, Tcp_urgent_pointer,
        Tcp_time_relative, Tcp_time_delta, Tcp_analysis_bytes_in_flight, Tcp_analysis_push_bytes_sent, Udp, Icmp, Icmp_ip_hdr_len,
        Icmp_ip_len, Icmp_ip_ttl, Icmp_ip_dsfield_dscp, Icmp_ip_dsfield_ecn, Has_bot,  size
    ]
    # Entropy_src_normalized, Entropy_dst_normalized,     

    #Escrever Array em .csv
    with open(CSV, mode='a', newline='') as arquivo_csv:
        writer = csv.writer(arquivo_csv)
        
        # Escreva o novo registro no arquivo CSV
        writer.writerow(array)
    atualiza_hora()