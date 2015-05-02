练习1:实现	first-fit	连续物理内存分配算法(需要编程)  
在实现first	fit	内存分配算法的回收函数时,要考虑地址连续的空闲块之间的合并操作。提示:在建立空闲页块链表时,需要按  
照空闲页块起始地址来排序,形成一个有序的链表。可能会修改default_pmm.c中的default_init,default_init_memmap,  
default_alloc_pages,	default_free_pages等相关函数。请仔细查看和理解default_pmm.c中的注释。  

>简要说明你的设计实现过程:  
首先理解各个函数变量的含义以及一些函数的用法:  
简要叙述如下:  
struct Page {
    int ref;                        // page frame's reference counter  
    uint32_t flags;                 // array of flags that describe the status of the page frame  
    unsigned int property;          // the num of free block, used in first fit pm manager  
    list_entry_t page_link;         // free list link  
};
property是记录块中页的个数  	
flag中有两个字段:
#define PG_reserved  
#define PG_property  
reserved 表示权限  
property 表示是不是这一块的头页
其实我认为property为1的页与list_entry_t是可以进行一些转化的,恰当地运用好这一点可以非常好的降低编程难度.  
SetPageProperty(p);//设置页空闲
set_page_ref(p, 0);//索引置为0  
对页表初始化进行如下操作:
 for (; p != base + n; p ++) {
        assert(PageReserved(p));
        p->flags = p->property = 0;
        SetPageProperty(p);
        set_page_ref(p, 0);
    }

分配内存时:
由开头指针进行搜索,
初始化过后根据最先匹配的方法分配内存,找到第一个符合大小要求的块;
进行分配操作,如果有剩余,在空闲块列表中添加新的空闲块.
释放空间时:  
首先根据地址的大小关系操作,找到待插的位置,
 while(((le = list_next(le)) != &free_list)) {
    	      pp = le2page(le, page_link);
    	      if (pp >= base)//(pp !=base
    	    	  break;
}	
注意,此时判断条件为pp >= base,因为此时维护的空闲块组为按地址排序的,
然后该改变块内的一系列标志位,  
for (; p != base + n; p ++) {
        assert(!PageReserved(p) && !PageProperty(p));
        p->flags = 0;
        SetPageProperty(p);
        p->property = 0;
        set_page_ref(p, 0);
    }
然后进行合并
for(p=base;p<base+n;p++){
      list_add_before(le, &(p->page_link));
}

