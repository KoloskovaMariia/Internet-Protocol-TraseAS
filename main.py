import sys
import os
import re
from urllib.request import urlopen
from prettytable import PrettyTable

reIP = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
reAS = re.compile("[Oo]riginA?S?: *([\d\w]+?)\n")
reCountry = re.compile("[Cc]ountry: *([\w]+?)\n")
reProvider = re.compile("mnt-by: *([\w\d-]+?)\n")


def get_ip(name):
    p = os.popen(f"tracert -4 {name}")  # использование командной строки
    stdout = p.read()
    return reIP.findall(stdout)  # парснг по регулярному выражению


def parce_site_answer(site, reg):
    try:
        a = reg.findall(site)  # вводим id
        return a[0]
    except:  # если неправильный
        return ''


def is_grey_ip(ip):
    return ip.startswith('192.168.') \
           or ip.startswith('10.') \
           or (ip.startswith('172.')
               and 15 < int(ip.split('.')[1]) < 32)


def get_inf_ip(ip):
    if is_grey_ip(ip):
        return ip, '', '', ''
    url = f"https://www.nic.ru/whois/?searchWord={ip}"
    try:
        with urlopen(url) as f:
            site = f.read().decode('utf-8')
            return ip, parce_site_answer(site, reAS), parce_site_answer(site, reCountry), \
                   parce_site_answer(site, reProvider)
    except:
        return ip, '', '', ''


def make_table(ips):
    th = ["№", "IP", "AS Name", "Country", "Provider"]
    td_data = []
    n = 0
    for i in ips:
        info = get_inf_ip(str(i))
        td_data.append(n)
        td_data.extend(info)
        n += 1
    columns = len(th)
    table = PrettyTable(th)
    while td_data:
        table.add_row(td_data[:columns])
        td_data = td_data[columns:]
    print(table)


def main():
    if len(sys.argv) < 2:  # следим за корректностью ввода
        print('Usage: python TraceAS.py \'name or ip\'')
        sys.exit(1)
    ip_arr = get_ip(sys.argv[1])
    make_table(ip_arr)


if __name__ == '__main__':
    main()
