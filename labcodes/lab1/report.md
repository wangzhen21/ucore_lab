# Lab1 erport

## [练习1]

[练习1.1] 操作系统镜像文件 ucore.img 是如何一步一步生成的?(需要比较详细地解释 Makefile 中
每一条相关命令和命令参数的含义,以及说明命令导致的结果)

```	
>
生成ucore.img，首先需要生成bootblock、kernel
>生成kernel代码为:
$(kernel): tools/kernel.ld

$(kernel): $(KOBJS)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
	@$(OBJDUMP) -S $@ > $(call asmfile,kernel)
	@$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)

生成kernel需要kernel.ld init.o readline.o stdio.o kdebug.o
kmonitor.o panic.o clock.o console.o intr.o picirq.o trap.o
trapentry.o vectors.o pmm.o  printfmt.o string.o
以生成init.o文件为例,
实际命令为
gcc -Ikern/init/ -fno-builtin -Wall -ggdb -m32 \
	-gstabs -nostdinc  -fno-stack-protector \
	-Ilibs/ -Ikern/debug/ -Ikern/driver/ \
	-Ikern/trap/ -Ikern/mm/ -c kern/init/init.c \
	-o obj/kern/init/init.o
生成kernel时命令如下:
ld -m    elf_i386 -nostdlib -T tools/kernel.ld -o bin/kernel \
	obj/kern/init/init.o obj/kern/libs/readline.o \
	obj/kern/libs/stdio.o obj/kern/debug/kdebug.o \
	obj/kern/debug/kmonitor.o obj/kern/debug/panic.o \
	obj/kern/driver/clock.o obj/kern/driver/console.o \
	obj/kern/driver/intr.o obj/kern/driver/picirq.o \
	obj/kern/trap/trap.o obj/kern/trap/trapentry.o \
	obj/kern/trap/vectors.o obj/kern/mm/pmm.o \
	obj/libs/printfmt.o obj/libs/string.o
	其中新出现的关键参数为
	T <scriptfile>  让连接器使用指定的脚本
>生成bootblock的相关代码为
# create bootblock
bootfiles = $(call listf_cc,boot)
$(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),$(CFLAGS) -Os -nostdinc))

bootblock = $(call totarget,bootblock)

$(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
	@$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
	@$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
	@$(call totarget,sign) $(call outfile,bootblock) $(bootblock)

$(call create_target,bootblock)
生成bootblock首先需要生成bootasm.o、bootmain.o、sign.
	>obj/boot/bootasm.o, obj/boot/bootmain.o
	生成bootasm.o,bootmain.o的相关makefile代码为
	bootfiles = $(call listf_cc,boot) 
	$(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),\
			$(CFLAGS) -Os -nostdinc))
		 实际代码由宏批量生成
	生成bootasm.o需要bootasm.S
	实际命令为
	gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs \
		-nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc \
		-c boot/bootasm.S -o obj/boot/bootasm.o
	其中关键的参数为
		-ggdb  生成可供gdb使用的调试信息。这样才能用qemu+gdb来调试bootloader or ucore。
		-m32  生成适用于32位环境的代码。我们用的模拟硬件是32bit的80386，所以ucore也要是32位的软件。
		-gstabs生成stabs格式的调试信息。这样要ucore的monitor可以显示出便于开发者阅读的函数调用栈信息
		-nostdinc  不使用标准库。标准库是给应用程序用的，我们是编译ucore内核，OS内核是提供服务的，所以所有的服务要自给自足。
		-fno-stack-protector  不生成用于检测缓冲区溢出的代码。这是for 应用程序的，我们是编译内核，ucore内核好像还用不到此功能。
		-Os  为减小代码大小而进行优化。根据硬件spec，主引导扇区只有512字节，我们写的简单bootloader的最终大小不能大于510字节。
		-I<dir>  添加搜索头文件的路径
	生成bootmain.o需要bootmain.c
	实际命令为
	gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc \
	-fno-stack-protector -Ilibs/ -Os -nostdinc \
	-c boot/bootmain.c -o obj/boot/bootmain.o
	新出现的关键参数有
	-fno-builtin  除非用__builtin_前缀，否则不进行builtin函数的优化
	>生成sign工具的makefile代码为
		$(call add_files_host,tools/sign.c,sign,sign)
		$(call create_target_host,sign,sign)
	实际命令为:
		gcc -Itools/ -g -Wall -O2 -c tools/sign.c \
		 	-o obj/sign/tools/sign.o
		gcc -g -Wall -O2 obj/sign/tools/sign.o -o bin/sign
	 首先生成bootblock.o
	ld -m    elf_i386 -nostdlib -N -e start -Ttext 0x7C00 \
		obj/boot/bootasm.o obj/boot/bootmain.o -o obj/bootblock.o
	 其中关键的参数为
		-m <emulation>  模拟为i386上的连接器
		-nostdlib  不使用标准库
		-N  设置代码段和数据段均可读写
		-e <entry>  指定入口
		-Ttext  制定代码段开始位置
	拷贝二进制代码bootblock.o到bootblock.out
	objcopy -S -O binary obj/bootblock.o obj/bootblock.out
	    其中关键的参数为
	    -S  移除所有符号和重定位信息
            -O <bfdname>  指定输出格式
	使用sign工具处理bootblock.out，生成bootblock
	bin/sign obj/bootblock.out bin/bootblock
生成完毕bootblock、kernel之后,由以下三步完成操作
生成一个有10000个块的文件，每个块默认512字节，用0填充
dd if=/dev/zero of=bin/ucore.img count=10000
把bootblock中的内容写到第一个块s
dd if=bin/bootblock of=bin/ucore.img conv=notrunc 
从第二个块开始写kernel中的内容
dd if=bin/kernel of=bin/ucore.img seek=1 conv=notrunc

[练习1.2] 一个被系统认为是符合规范的硬盘主引导扇区的特征是什么?

从生成sign工具的代码来看，
 if (st.st_size > 510) {
        fprintf(stderr, "%lld >> 510!!\n", (long long)st.st_size);
        return -1;
    }
    char buf[512];
一个磁盘主引导扇区只有512字节。且
 buf[510] = 0x55;
 buf[511] = 0xAA;
第510个字节是0x55，
第511个字节是0xAA。
[练习2.1] 从 CPU 加电后执行的第一条指令开始,单步跟踪 BIOS 的执行。
首先改写Makefile文件 
debug: $(UCOREIMG)
		$(V)$(TERMINAL) -e "$(QEMU) -S -s -d in_asm -D $(BINDIR)/q.log -parallel stdio -hda $< -serial null"
		$(V)sleep 2
		$(V)$(TERMINAL) -e "gdb -q -tui -x tools/gdbinit"
修改lab1/tools/gdbmit
set	architecture	i8086
target	remote	:1234

在lab1目录下执行make debug

执行命令step等单步跟踪指令进行单步跟踪还有(next,nexti,stepi)功能各不相同.

[练习2.2] 在初始化位置0x7c00 设置实地址断点,测试断点正常。
修改lab1/tools/gdbmit为
set architecture i8086
target	remote	:1234
b *0x7c00
continue
 x /2i $pc
得到:
Breakpoint 1, 0x00007c00 in ?? ()
	=> 0x7c00:      cli    
	   0x7c01:      cld    

[练习2.3] 在调用qemu 时增加-d in_asm -D q.log 参数，便可以将运行的汇编指令保存在q.log 中。
将执行的汇编代码与bootasm.S 和 bootblock.asm 进行比较，看看二者是否一致。

>执行后q.log里面是
----------------
IN: 
0xfffffff0:  ljmp   $0xf000,$0xe05b

----------------
IN: 
0x000fe05b:  cmpl   $0x0,%cs:0x65a4
0x000fe062:  jne    0xfd2b9

----------------
IN: 
0x000fe066:  xor    %ax,%ax
0x000fe068:  mov    %ax,%ss

----------------
IN: 
0x000fe06a:  mov    $0x7000,%esp

----------------
IN: 
0x000fe070:  mov    $0xf3c4f,%edx
0x000fe076:  jmp    0xfd12a

----------------
IN: 
0x000fd12a:  mov    %eax,%ecx
0x000fd12d:  cli    
0x000fd12e:  cld    
0x000fd12f:  mov    $0x8f,%eax
0x000fd135:  out    %al,$0x70
0x000fd137:  in     $0x71,%al
0x000fd139:  in     $0x92,%al
0x000fd13b:  or     $0x2,%al
0x000fd13d:  out    %al,$0x92
0x000fd13f:  lidtw  %cs:0x66c0
0x000fd145:  lgdtw  %cs:0x6680
0x000fd14b:  mov    %cr0,%eax
0x000fd14e:  or     $0x1,%eax
0x000fd152:  mov    %eax,%cr0

----------------
IN: 
0x000fd155:  ljmpl  $0x8,$0xfd15d

----------------
IN: 
0x000fd15d:  mov    $0x10,%eax
0x000fd162:  mov    %eax,%ds

----------------
IN: 
0x000fd164:  mov    %eax,%es

----------------
IN: 
0x000fd166:  mov    %eax,%ss

----------------
IN: 
0x000fd168:  mov    %eax,%fs

----------------
IN: 
0x000fd16a:  mov    %eax,%gs
0x000fd16c:  mov    %ecx,%eax
0x000fd16e:  jmp    *%edx

----------------

其与bootasm.S和bootblock.asm中的代码一致。

## [练习3]
分析bootloader 进入保护模式的过程。

从`%cs=0 $p

首先清理环境：包括将flag置0和将段寄存器置0
```
	.code16
	    cli
	    cld
	    xorw %ax, %ax
	    movw %ax, %ds
	    movw %ax, %es
	    movw %ax, %ss
```

 开启A20 Gate：取消对A20地址线的禁止,使可以访问4G的内存空间。
```
seta20.1:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.1

    movb $0xd1, %al                                 # 0xd1 -> port 0x64
    outb %al, $0x64                                 # 0xd1 means: write data to 8042's P2 port

seta20.2:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.2
    movb $0xdf, %al                                 # 0xdf -> port 0x60
    outb %al, $0x60                                 # 0xdf = 11011111, means set P2's A20 bit(the 1 bit) to 1
```

初始化GDT表：一个简单的GDT表和其描述符已经静态储存在引导区中，载入即可
```
	    lgdt gdtdesc
```

进入保护模式：通过将cr0寄存器PE位置1便开启了保护模式
```
	    movl %cr0, %eax
	    orl $CR0_PE_ON, %eax
	    movl %eax, %cr0
```

通过长跳转更新cs的基地址
```
	 ljmp $PROT_MODE_CSEG, $protcseg
	.code32
	protcseg:
```

设置段寄存器，并建立堆栈
```
	    movw $PROT_MODE_DSEG, %ax
	    movw %ax, %ds
	    movw %ax, %es
	    movw %ax, %fs
	    movw %ax, %gs
	    movw %ax, %ss
	    movl $0x0, %ebp
	    movl $start, %esp
```
转到保护模式完成，进入boot主方法
```
	    call bootmain
```
## [练习4]
分析bootloader加载ELF格式的OS的过程。

首先看readsect函数，
函数用到了GCC内联汇编

`readsect`从设备的第secno扇区读取数据到dst位置
```
	static void
	readsect(void *dst, uint32_t secno) {
	    waitdisk();   //waitdisk(void) {    while ((inb(0x1F7) & 0xC0) != 0x40)/* do nothing */

         // outb(uint16_t port, uint8_t data) {
         // asm volatile ("outb %0, %1" :: "a" (data), "d" (port));
         // }
	    outb(0x1F2, 1);                         // 设置读取扇区的数目为1
	    outb(0x1F3, secno & 0xFF);
	    outb(0x1F4, (secno >> 8) & 0xFF);
	    outb(0x1F5, (secno >> 16) & 0xFF);
	    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);// 上面四条指令联合制定了扇区号
	        
	    outb(0x1F7, 0x20);                      // 0x20命令，读取扇区
	
	    waitdisk();

	    insl(0x1F0, dst, SECTSIZE / 4);         // 读取到dst位置，
	}
```
接下来是 是readseg,调用readsect，实现从设备读取任意长度的内容。
```
	readseg(uintptr_t va, uint32_t count, uint32_t offset) {
        uintptr_t end_va = va + count;

    		// round down to sector boundary
    	va -= offset % SECTSIZE;

    	// translate from bytes to sectors; kernel starts at sector 1
    		uint32_t secno = (offset / SECTSIZE) + 1;

        // If this is too slow, we could read lots of sectors at a time.
        // We'd write more to memory than asked, but it doesn't matter --
        // we load in increasing order.
       for (; va < end_va; va += SECTSIZE, secno ++) {
         readsect((void *)va, secno);
       }
}
```

在bootmain函数中，
```
	void
	bootmain(void) {
	    // 首先读取ELF文件的头部
	    readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);
	    
	    // 判断是否是合法的ELF文件
	    if (ELFHDR->e_magic != ELF_MAGIC) {
	        goto bad;
	    }
	
	    struct proghdr *ph, *eph;
	
	    // ELF头部有描述ELF文件应加载到内存什么位置的描述表，
	    // 先将描述表的头地址存在ph
	    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
	    eph = ph + ELFHDR->e_phnum;

	    // 按照描述表将ELF文件中数据载入内存
	    for (; ph < eph; ph ++) {
	        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
	    }
	    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();
	
	bad:
	    outw(0x8A00, 0x8A00);
	    outw(0x8A00, 0x8E00);
	    while (1);
	}
```
## [练习5] 
实现函数调用堆栈跟踪函数 

ss:ebp指向的堆栈位置储存着caller的ebp，以此为线索可以得到所有使用堆栈的函数ebp。
ss:ebp+4指向caller调用时的eip，ss:ebp+8等是（可能的）参数。
>输出为:  
Special kernel symbols:
  entry  0x00100000 (phys)
  etext  0x001032e0 (phys)
  edata  0x0010ea16 (phys)
  end    0x0010fd20 (phys)
Kernel executable memory footprint: 64KB
ebp:0x00007b08 eip:0x001009a6 args:0x00010094  0x00000000  0x00007b38  0x00100092  
    kern/debug/kdebug.c:305: print_stackframe+21
ebp:0x00007b18 eip:0x00100cb2 args:0x00000000  0x00000000  0x00000000  0x00007b88  
    kern/debug/kmonitor.c:125: mon_backtrace+10
ebp:0x00007b38 eip:0x00100092 args:0x00000000  0x00007b60  0xffff0000  0x00007b64  
    kern/init/init.c:48: grade_backtrace2+33
ebp:0x00007b58 eip:0x001000bb args:0x00000000  0xffff0000  0x00007b84  0x00000029  
    kern/init/init.c:53: grade_backtrace1+38
ebp:0x00007b78 eip:0x001000d9 args:0x00000000  0x00100000  0xffff0000  0x0000001d  
    kern/init/init.c:58: grade_backtrace0+23
ebp:0x00007b98 eip:0x001000fe args:0x001032fc  0x001032e0  0x0000130a  0x00000000  
    kern/init/init.c:63: grade_backtrace+34
ebp:0x00007bc8 eip:0x00100055 args:0x00000000  0x00000000  0x00000000  0x00010094  
    kern/init/init.c:28: kern_init+84
ebp:0x00007bf8 eip:0x00007d68 args:0xc031fcfa  0xc08ed88e  0x64e4d08e  0xfa7502a8  
    <unknow>: -- 0x00007d67 --
++ setup timer interrupts

输出中,堆栈最深的一层为
其对应的是第一个使用堆栈的函数，bootmain.c中的bootmain。
bootloader设置的堆栈从0x7c00开始，使用"call bootmain"转入bootmain函数。call指令压栈，所以bootmain中ebp为0x7bf8。  


## [练习6]
完善中断初始化和处理

[练习6.1] 中断向量表中一个表项占多少字节？其中哪几位代表中断处理代码的入口？

中断向量表一个表项占用8字节，其中2-3字节是段选择子，0-1字节和6-7字节拼成位移，
两者联合便是中断处理程序的入口地址。

[练习6.2] 请编程完善kern/trap/trap.c中对中断向量表进行初始化的函数idt_init。

见代码

[练习6.3] 请编程完善trap.c中的中断处理函数trap，在对时钟中断进行处理的部分填写trap函数

见代码



## [练习7]

增加syscall功能，即增加一用户态函数（可执行一特定系统调用：获得时钟计数值），
当内核初始完毕后，可从内核态返回到用户态的函数，而用户态的函数又通过系统调用得到内核态的服务

在idt_init中，将用户态调用SWITCH_TOK中断的权限打开。
	SETGATE(idt[T_SWITCH_TOK], 1, KERNEL_CS, __vectors[T_SWITCH_TOK], 3);

在trap_dispatch中，将iret时会从堆栈弹出的段寄存器进行修改
	对TO User
```
	    tf->tf_cs = USER_CS;
	    tf->tf_ds = USER_DS;
	    tf->tf_es = USER_DS;
	    tf->tf_ss = USER_DS;
```
	对TO Kernel

```
	    tf->tf_cs = KERNEL_CS;
	    tf->tf_ds = KERNEL_DS;
	    tf->tf_es = KERNEL_DS;
```

在lab1_switch_to_user中，调用T_SWITCH_TOU中断。
注意从中断返回时，会多pop两位，并用这两位的值更新ss,sp，损坏堆栈。
所以要先把栈压两位，并在从中断返回后修复esp。
```
	asm volatile (
	    "sub $0x8, %%esp \n"
	    "int %0 \n"
	    "movl %%ebp, %%esp"
	    : 
	    : "i"(T_SWITCH_TOU)
	);
```

在lab1_switch_to_kernel中，调用T_SWITCH_TOK中断。
注意从中断返回时，esp仍在TSS指示的堆栈中。所以要在从中断返回后修复esp。
```
	asm volatile (
	    "int %0 \n"
	    "movl %%ebp, %%esp \n"
	    : 
	    : "i"(T_SWITCH_TOK)
	);
```

但这样不能正常输出文本。根据提示，在trap_dispatch中转User态时，将调用io所需权限降低。
```
	tf->tf_eflags |= 0x3000;
```
