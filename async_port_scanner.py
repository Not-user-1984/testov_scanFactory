import asyncio
import json
import subprocess


async def scan(ip_address, port_list):
    cmd = ["nmap", "-p", ",".join(port_list), ip_address]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE)
        output = await proc.stdout.read()
        return output.decode()
    except Exception as e:
        print(f"Ошибка сканирования {ip_address}: {e}")


async def parse_output(output):
    open_ports = []
    closed_ports = []
    for line in output.splitlines():
        if "tcp" in line:
            port_status = line.split()[1]
            port_number = line.split("/")[0]
            if port_status == "open":
                open_ports.append(port_number)
            elif port_status == "closed":
                closed_ports.append(port_number)
    return {"open_ports": open_ports, "closed_ports": closed_ports}


async def main():
    # Чтение списка IP-адресов из файла
    with open("ip_addresses.txt") as f:
        ip_list = f.read().splitlines()

    # Чтение списка портов из файла
    with open("port_list.txt") as f:
        port_list = f.read().splitlines()

    results = {}

    tasks = []
    for ip_address in ip_list:
        task = asyncio.create_task(scan(ip_address, port_list))
        tasks.append(task)

    # Ожидание завершения всех задач
    completed_tasks = asyncio.gather(*tasks)
    outputs = await completed_tasks

    # Парсинг вывода Nmap для определения открытых и закрытых портов
    tasks = []
    for i, output in enumerate(outputs):
        task = asyncio.create_task(parse_output(output))
        tasks.append(task)

        # Добавление результатов в словарь
        results[ip_list[i]] = {}

    # Ожидание завершения всех задач
    completed_tasks = asyncio.gather(*tasks)
    outputs = await completed_tasks

    # Обновление результатов в словаре
    for i, result in enumerate(outputs):
        ip_address = ip_list[i]
        results[ip_address].update(result)

    # Вывод результатов в формате json
    print(json.dumps(results, indent=4))


if __name__ == "__main__":
    asyncio.run(main())
