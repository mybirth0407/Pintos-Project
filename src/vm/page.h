#ifndef VM_PAGE_H
#define VM_PAGE_H

struct vm_entry
  {
    uint8_t type;                   /* VM_BIN, VM_FILE, VM_ANON */
    void *vaddr;                    /* vm_entry 가 관리하는 가상 주소 */
    bool writable;                  /* True 일 경우 해당 주소에 write 가능 */
    bool is_loaded;                 /* 물리 메모리의 탑재 여부 */
    bool pinned;                    /*  */
    struct file *file;              /* 가상 주소와 매핑된 파일 */
    struct list_elem mmap_elem;     /* mmap list element */
    size_t offset;                  /* File offset */
    size_t read_bytes;              /* 읽은 바이트 수 */
    size_t zero_bytes;              /* 메모리에 0 의 개수 */
    size_t swap_slot;               /* 스왑할 슬롯 */
    struct hash_elem elem;          /* Hash table 의 element */
  }

/* hash_init () 을 사용하여 Hash table 초기화 */
void vm_init (struct hash *vm);
/* hash_destroy () 를 사용하여 Hash table 초기화 */
void vm_destroy (struct hash *vm);
/* Chained Hash table,
   Use Fowler-Noll-Vo (FNV) 32bit Hash function
   Return Hash function location */
static unsigned vm_hash_func (const struct hash_elem *e, void aux *UNUSED);
/* a 의 주소 값이 b 보다 작을 시 true */
static bool vm_less_func (const struct hash_elem *a,
                          const struct hash_elem *b,
                          void *aux UNUSED);
/* palloc_free_page (), free () 를 사용하여 메모리 해제 */
static void vm_destroy_func (struct hash_elem *e, void *aux UNUSED)
/* vaddr 에 해당하는 vm_entry 검색 */
struct vm_entry *find_vme (void *vaddr);
/* hash_insert () 를 사용하여 vm_entry 를 hash table 에 삽입 
   vm_entry 삽입 성공 시 true, 이미 존재하면 false */
bool insert_vme (struct hash *vm, struct vm_entry *vme);
/* hash_delete () 를 사용하여 vm_entry 를 hash table 에서 제거 */
bool delete_vme (struct hash *vm, struct vm_entry *vme);

#endif /* vm/page.h */
