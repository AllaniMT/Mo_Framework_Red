$ipAdressesFilePath = "THE PATH OF THE TXT FILE, WHERE THE IP ADRESSES ARE SAVED."

$outputFilePath = "THE PATH OF THE TXT FILE, WHERE THE RESULT OF THE SCAN WILL BE WRITED."

$ports = @(445, 3389, 22)

# You can add the port, that you want to scan in the var. $ports. Here are examples of well-known ports that can be compromised

#Port 22 (SSH) - Secure Shell

#Port 80 (HTTP) - Hypertext Transfer Protocol

#Port 443 (HTTPS) - HTTP Secure

#Port 445 (SMB) - Server Message Block

#Port 3389 (RDP) - Remote Desktop Protocol

#Port 1433 (MS-SQL) - Microsoft SQL Server

#Port 3306 (MySQL) - MySQL Database Server

#Port 23 (TELNET) - Telnet Protocol

#Port 25 (SMTP) - Simple Mail Transfer Protocol

#Port 21 (FTP) - File Transfer Protocol

$ipAddressesAsArray = Get-Content -Path $ipAdressesFilePath

$results = @()

foreach ($ipAddress in $ipAddressesAsArray) {
    # Check if the IP address is in CIDR notation
    if ($ipAddress -like "*/*") {
        $cidrIP = $ipAddress.Split("/")[0]
        $cidrMask = [int]$ipAddress.Split("/")[1]
        $subnet = New-Object System.Net.IPAddress(
            ([System.Net.IPAddress]::Parse($cidrIP)).GetAddressBytes(),
            $cidrMask
        )
        $network = [System.Net.NetworkInformation.IPNetwork]::New(
            $subnet,
            $cidrMask
        )
        foreach ($ip in $network) {
            $result = @{
                "Scanned IP Address" = $ip.IPAddressToString
                "Open Ports"         = @()
            }
            foreach ($port in $ports) {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.ReceiveTimeout = 200
                $tcpClient.SendTimeout = 200
                try {
                    $tcpClient.Connect($ip.IPAddressToString, $port)
                    if ($tcpClient.Connected) {
                        $result["Open Ports"] += $port
                        Write-Host ("TCP port {0} is open on {1}" -f $port, $ip.IPAddressToString)
                    }
                }
                catch {
                    Write-Host ("TCP port {0} is closed on {1}" -f $port, $ip.IPAddressToString)
                }
                finally {

                    $tcpClient.Close()
                }
            }
            $results += New-Object PSObject -Property $result
        }
    }
    else {
        $result = @{
            "Scanned IP Address" = $ipAddress
            "Open Ports"         = @()
        }
        foreach ($port in $ports) {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.ReceiveTimeout = 200
            $tcpClient.SendTimeout = 200
            try {
                $tcpClient.Connect($ipAddress, $port)
                if ($tcpClient.Connected) {
                    $result["Open Ports"] += $port
                    Write-Host ("TCP port {0} is open on {1}" -f $port, $ipAddress)
                }
            }
            catch {
                Write-Host ("TCP port {0} is open on {1}" -f $port, $ipAddress)
            }
            finally {
                $tcpClient.Close()
            }
        }
        $results += New-Object PSObject -Property $result
    }
    Write-Host "============"
}

$results | Export-Csv -Path $outputFilePath -NoTypeInformation
