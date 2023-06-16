package main

import (
    "encoding/json"
    "fmt"
    "bufio"
    "os"
    "os/exec"
    "strings"
)

func scan(ipAddr string, ports []string) (string, error) {
    cmd := exec.Command("nmap", append([]string{"-p", strings.Join(ports, ","), ipAddr}, "-oG", "-")...)
    out, err := cmd.Output()
    return string(out), err
}

func main() {
    // Чтение списка IP-адресов из файла
    ipFile, err := os.Open("ip_addresses.txt")
    if err != nil {
        panic(err)
    }
    defer ipFile.Close()

    var ipList []string
    scanner := bufio.NewScanner(ipFile)
    for scanner.Scan() {
        ipList = append(ipList, scanner.Text())
    }
    if err := scanner.Err(); err != nil {
        panic(err)
    }

    // Чтение списка портов из файла
    portFile, err := os.Open("port_list.txt")
    if err != nil {
        panic(err)
    }
    defer portFile.Close()

    var portList []string
    scanner = bufio.NewScanner(portFile)
    for scanner.Scan() {
        portList = append(portList, scanner.Text())
    }
    if err := scanner.Err(); err != nil {
        panic(err)
    }

    results := make(map[string]interface{})

    for _, ipAddr := range ipList {
        output, err := scan(ipAddr, portList)
        if err != nil {
            panic(err)
        }

        // Парсинг вывода Nmap для определения открытых и закрытых портов
        openPorts := make([]string, 0)
        closedPorts := make([]string, 0)
        for _, line := range strings.Split(output, "\n") {
            if strings.Contains(line, "Ports:") {
                for _, portLine := range strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "Ports:")), ", ") {
                    portFields := strings.Fields(portLine)
                    if len(portFields) > 1 && portFields[1] == "open" {
                        openPorts = append(openPorts, portFields[0])
                    } else if len(portFields) > 1 && portFields[1] == "closed" {
                        closedPorts = append(closedPorts, portFields[0])
                    }
                }
            }
        }

        // Добавление результатов в словарь
        results[ipAddr] = map[string]interface{}{
            "open_ports":   openPorts,
            "closed_ports": closedPorts,
        }
    }

    // Вывод результатов в формате json
    jsonStr, err := json.MarshalIndent(results, "", "    ")
    if err != nil {
        panic(err)
    }
    fmt.Println(string(jsonStr))
}