## bomb_squad - 130 (Reversing) ##
#### Writeup by r3ndom_ #####
Created: 2016-4-17

### Problem ###
Welcome to the bomb squad. Your first task is to diffuse this test bomb!
`nc problems2.2016q1.sctf.io 1340`

### Hint ###
None

## Answer ##

### Overview ###
Standard binary bomb, solve each phase of the algo.

### Details ###

I kinda went hella ham on figuring out the vuln with kobayashi maru so I decompiled a good portion of the program, heres my _partial_ work on decompiling the binary:

```c
// bomb_squad.c
#include <stdio.h>
#include <stdlib.h>

struct node
{
    node* nodes[4];
    char name[8];
    int value;
};

bool phase1_solved = false;
bool phase2_solved = false;
bool phase3_solved = false;
bool phase4_solved = false;

char buff[0x100];

char* get_line()
{
    int cnt = 0;
    while (1)
    {
        char ch = getchar();
        if (ch == '\n' || cnt > 0xff)
            break;
        buff[cnt++] = ch;
    }
    buff[cnt] = 0;
    return buff;
}

void phase_1()
{
    puts("Give me a number!");
    char* input = get_line();
    // Look I'm never sure if the compiler follows order of operation so I nest my
    // parentheses like no tomorrow.
    if ((((atoi(input) * 2 / 37) - 18) * 3) - 1 != 1337 )
        explode_bomb();
    phase1_solved = true;
}

int func2(int n)
{
    // 2 ** n
    int res = 1;
    for (int i = 0; i < n; ++i)
    {
        res *= 2;
    }
    return res;
}

void phase_2()
{
    int numbers[6];
    puts("Give me an array of numbers!");
    char* line = get_line();
    sscanf(line, "[%d, %d, %d, %d, %d, %d]", 
        &numbers[0], 
        &numbers[1], 
        &numbers[2], 
        &numbers[3], 
        &numbers[4], 
        &numbers[5]);

    if (numbers[0] != 1)
        explode_bomb();
    for (int i = 1; i < 6; ++i)
    {
        int next = numbers[i - 1] + numbers[i];
        if (next != func2(i))
            explode_bomb();
    }
    phase2_solved = true;
}

char keys[] = "qagvCYiheXulrpszNLwMtodbVx";
char lastentered = 0;

void phase_3()
{
    char* input = get_line();
    char* randomChars = "rqzzepiwMLepiwYsLYtpqpvzLsYeM";
    while ( 1 )
    {
        char ch = *(char*)(input++);
        if (!ch)
            break;

        if (ch < 'a' || ch > '{' )
            explode_bomb();

        if ( *(char*)randomChars++ != keys[ch - 'a'] )
            explode_bomb();

        lastentered = ch;
    }
    phase3_solved = true;
}

// nodes 1 - 6 are declared similar to below
node n1, n2, n3, n4, n5, n6;

node n1 = {&n2, &n3, &n4, &n5, 0x314e, 0, 10};
node n2 = {&n3, &n4, &n5, &n6, 0x324e, 0, 7};
node n3 = {&n1, &n2, &n4, &n6, 0x334e, 0, 9};
node n4 = {&n4, &n4, &n4, &n4, 0x344e, 0, 2};
node n5 = {&n1, &n6, &n1, &n6, 0x354e, 0, 16};
node n6 = {&n6, &n6, &n6, &n6, 0x364e, 0, 27};

void phase_4()
{
    int intArray[7];
    char* input = get_line();
    sscanf(input, "%d %d %d %d %d %d %d", 
        &intArray[0], 
        &intArray[1], 
        &intArray[2], 
        &intArray[3], 
        &intArray[4], 
        &intArray[5], 
        &intArray[6]);

    node* nodeptr = n1;
    int final = n1->value;
    for (int i = 0; i <= 6; ++i)
    {
        if (intArray[i] < 0 || intArray[i] > 3)
            explode_bomb();
        nodeptr = nodeptr->nodes[intArray[i]];
        final += nodeptr->value;
    }

    if (final != 95)
        explode_bomb();

    phase4_solved = true;
}

void secret_phase()
{
    puts("secret phasorz");
    node* pNodes[6] = 
    {
        &n1,
        &n2,
        &n3,
        &n4,
        &n5,
        &n6
    };

    for (int i = 0; i < 6; ++i)
    {
        printf("Rename node #%d to: ", i+1);
        fgets(pNodes[i]->name, 9, stdin);
        *strchrnul(pNodes[i]->name, '\n') = 0;
        putchar('\n');
    }

    puts("ty babe");
}

bool verify_working()
{
    if (phase1_solved
        && phase2_solved
        && phase3_solved
        && phase4_solved
        && !keys[lastentered - 'a'])
    {
        secret_phase();
    }
    return true;
}

void print_flag()
{
    if (verify_working())
    {
        puts("Gratz");
        system("cat flag.txt");
    }
    exit(1);
}

int main()
{
    setvbuf(stdout, 0, 2, 0);
    puts("Welcome to the bomb squad! Your first task: Diffuse this practice bomb.");
    phase_1();
    puts("Phase 2 msg");
    phase_2();
    puts("Phase 3 msg");
    phase_3();
    puts("Phase 4 msg");
    phase_4();
    print_flag();
}
```

This is fairly close to the actual source, except this doesn't contain the most relevant parts to kobayashi maru.

Each phase can be solved in order via looking for where it explodes and making sure it never meets those conditions. 

Phase 1 8584 goes to 1337 via that equation. 

Phase 2 each value must be equal to 2**n - previous and be in brackets, comma seperated. So [1,1,3,5,11,21]

Phase 3 can be empty and as such just pressing enter at this phase is acceptable.

Phase 4 took a bit of work for me and my team, but we solved it using this MS paint image:

![](https://dl.dropboxusercontent.com/u/33547841/paths.png)

You start at 10 then add 7 values to get to 95. One correct node path is 3 0 3 0 3 0 0

So I wrote a little script to input all these values and then you get the flag!

```python
print '8584'
print '[1, 1, 3, 5, 11, 21]''
print ''
print '3 0 3 0 3 0 0'
```

Pipe that into nc for the server and you're done.

### Flag ###

The flag was `sctf{g00d_j0b_c4d3t}`
