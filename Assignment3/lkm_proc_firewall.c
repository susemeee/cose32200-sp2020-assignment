#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <asm/uaccess.h>

#define FORWARD_NET_ADDR "131.1.1.1"
#define BUFFER_SIZE 10000

#define PROC_DIRNAME "group37"
#define PROC_FILENAME_ADD "add"
#define PROC_FILENAME_DEL "del"
#define PROC_FILENAME_SHOW "show"

static struct proc_dir_entry* proc_dir;
static struct proc_dir_entry* proc_file_add;
static struct proc_dir_entry* proc_file_del;
static struct proc_dir_entry* proc_file_show;

char proc_write_buffer[BUFFER_SIZE];
char proc_read_buffer[BUFFER_SIZE];


unsigned int as_addr_to_net(char *str) {
  unsigned int arr[4];
  sscanf(str, "%d.%d.%d.%d", &arr[0], &arr[1], &arr[2], &arr[3]);
  return *(unsigned int *)arr;
}

char* as_net_to_addr(unsigned int addr, char str[]) {
  char add[16];
  unsigned char a = ((unsigned char *)&addr)[0];
  unsigned char b = ((unsigned char *)&addr)[1];
  unsigned char c = ((unsigned char *)&addr)[2];
  unsigned char d = ((unsigned char *)&addr)[3];
  sprintf(add, "%u.%u.%u.%u", a, b, c, d);
  sprintf(str, "%s", add);
  return str;
}

typedef enum {
  PROC_WRITE_TYPE_ADD,
  PROC_WRITE_TYPE_DEL,
} PROC_WRITE_TYPE;


typedef struct {
  /** index */
  int index;
  /** IOFP */
  char rule_type;
  /** 포트 번호 */
  int port;
  /** is_active */
  int is_active;

  struct list_head list;

} netfilter_rule;

static netfilter_rule rules = {
  .index = 0,
  .is_active = 0,
  .list = LIST_HEAD_INIT(rules.list),
};

static int is_in_netfilter_rules(char rule_type, int port) {
  netfilter_rule* rule = NULL;
  list_for_each_entry(rule, &rules.list, list) {
    if (rule != NULL && rule->is_active == 1 && rule->rule_type == rule_type && rule->port == port) {
      return 1;
    }
  }
  return 0;
}

static int add_netfilter_rules(char rule_type, int port) {

  netfilter_rule* rule = list_last_entry(&rules.list, netfilter_rule, list);
  int i = rule->index;

  if (rule_type != 'I' && rule_type != 'O' && rule_type != 'P' && rule_type != 'F') {
    printk(KERN_WARNING "add_netfilter_rules: Invalid rule type. Must be one of I, O, P, F.");
    return -1;
  }

  netfilter_rule* new_rule = (netfilter_rule*)kmalloc(sizeof(netfilter_rule), GFP_KERNEL);
  new_rule->index = i + 1;
  new_rule->rule_type = rule_type;
  new_rule->port = port;
  new_rule->is_active = 1;
  INIT_LIST_HEAD(&new_rule->list);
  list_add(&new_rule->list, &rule->list);
  return i;
}

/**
 * 특정 index의 Netfilter rule을 비활성화하는 함수
 */
static void remove_netfilter_rules(int i) {

  netfilter_rule* rule = NULL;
  list_for_each_entry(rule, &rules.list, list) {
    if (rule != NULL && rule->index == i) {
      rule->is_active = 0;
    }
  }
}


/**
 * TODO: init_net에 대한 설명
 */
extern struct net init_net;

/**
 * TODO: nf_hook_ops에 대한 설명
 */
static struct nf_hook_ops* hook_ops_pre = NULL;
static struct nf_hook_ops* hook_ops_post = NULL;
static struct nf_hook_ops* hook_ops_forward = NULL;

/**
 * TODO: netfilter_hook_func에 대한 설명
 */
static unsigned int _netfilter_hook_func(char rule_type, void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {

  if (!skb) {
    return NF_ACCEPT;
  }

  // https://elixir.bootlin.com/linux/v4.4/source/include/linux/ip.h#L23
  struct iphdr* ip_header = ip_hdr(skb);

  if (ip_header == NULL) {
    printk(KERN_WARNING "_netfilter_hook_func: ip_header is null!");
    return NF_ACCEPT;
  }

  char* direction;
  switch (rule_type) {
    case 'I':
      direction = "INBOUND";
      break;
    case 'O':
      direction = "OUTBOUND";
      break;
    case 'F':
      direction = "FORWARD";
      break;
    default:
      direction = "???";
  }

  char saddr[16];
  char daddr[16];
  as_net_to_addr(ip_header->saddr, saddr);
  as_net_to_addr(ip_header->daddr, daddr);

  /** TCP가 아닌 경우 */
  if (ip_header->protocol != IPPROTO_TCP) {
    return NF_ACCEPT;
  }

  struct tcphdr* tcp_header = tcp_hdr(skb);

  if (tcp_header == NULL) {
    printk(KERN_WARNING "_netfilter_hook_func: tcp_header is null!");
    return NF_ACCEPT;
  }

  int sport = ntohs(tcp_header->source);
  int dport = ntohs(tcp_header->dest);
  int syn = tcp_header->syn;
  int fin = tcp_header->fin;
  int ack = tcp_header->ack;
  int rst = tcp_header->rst;

  /** inbound packet의 경우, source port를 확인해야 함. */
  int target_port = rule_type == 'I' ? sport : dport;
  if (is_in_netfilter_rules(rule_type, target_port) != 0) {
    /** type, protocol, sport, dport, saddr, daddr, tcp bit */
    printk(KERN_INFO "DROP[%8s]: %d, %d, %d, %s, %s, %d%d%d%d", direction, ip_header->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);
    return NF_DROP;
  }

  /** proxy */
  if (is_in_netfilter_rules('P', dport) != 0) {
    ip_header->daddr = as_addr_to_net(FORWARD_NET_ADDR);
    tcp_header->dest = tcp_header->source;
    printk(KERN_INFO "PROXY[%8s]: %d, %d, %d, %s, %s, %d%d%d%d", direction, ip_header->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);
    return NF_ACCEPT;
  }

  /** type, protocol, sport, dport, saddr, daddr, tcp bit */
  printk(KERN_INFO "[%8s]: %d, %d, %d, %s, %s, %d%d%d%d", direction, ip_header->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);
  return NF_ACCEPT;

}

static unsigned int netfilter_hook_func_pre(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
  return _netfilter_hook_func('I', priv, skb, state);
}


static unsigned int netfilter_hook_func_post(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
  return _netfilter_hook_func('O', priv, skb, state);
}


static unsigned int netfilter_hook_func_forward(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
  return _netfilter_hook_func('F', priv, skb, state);
}


static ssize_t _proc_write(PROC_WRITE_TYPE type, struct file* file, const char __user *buf, size_t len, loff_t *ppos) {

  char rule_type;
  int port;
  int index;

  if (len > BUFFER_SIZE) {
    len = BUFFER_SIZE;
  }

  if (len > 0 && copy_from_user(proc_read_buffer, buf, len)) {
    return -EFAULT;
  }

  switch (type) {
    case PROC_WRITE_TYPE_ADD:
      sscanf(proc_read_buffer, "%c %d", &rule_type, &port);
      add_netfilter_rules(rule_type, port);
      break;
    case PROC_WRITE_TYPE_DEL:
      sscanf(proc_read_buffer, "%d", &index);
      remove_netfilter_rules(index);
      break;
  }

  return len;
}


static ssize_t proc_write_add(struct file* file, const char __user *buf, size_t len, loff_t *ppos) {
  printk(KERN_INFO "Firewall Module Add!!\n");
  return _proc_write(PROC_WRITE_TYPE_ADD, file, buf, len, ppos);
}

static ssize_t proc_write_del(struct file* file, const char __user *buf, size_t len, loff_t *ppos) {
  printk(KERN_INFO "Firewall Module Del!!\n");
  return _proc_write(PROC_WRITE_TYPE_DEL, file, buf, len, ppos);
}

/**
 * proc 파일이 read (e.g. cat /proc/PROC_FILENAME) 될 때 실행되는 부분.
 * user space에서는 리턴값(buffer_length)만큼 user_buffer를 읽음.
 */
static ssize_t proc_show_read(struct file* file, char __user* user_buffer, size_t count, loff_t* ppos) {

  int buffer_length = 0;

  if (*ppos > 0 || count < BUFFER_SIZE) {
    // user가 처음 read를 한 케이스가 아니거나(ppos > 0), read count가 buffer size보다 작을 경우, EOF(0)를 리턴한다.
    return 0;
  } else {

    netfilter_rule* rule = NULL;
    list_for_each_entry(rule, &rules.list, list) {
      if (rule != NULL && rule->is_active == 1) {
        buffer_length += sprintf(proc_write_buffer + buffer_length, "%d(%c): %d\n", rule->index, rule->rule_type, rule->port);
      }
    }

    // kernel -> user space로 buffer를 복사한다. 실패할 경우 segfault
    if (buffer_length > 0 && copy_to_user(user_buffer, proc_write_buffer, buffer_length)) {
      return -EFAULT;
    }

    // read seek position을 buffer_length만큼 이동
    *ppos = buffer_length;
    return buffer_length;
  }
}

static const struct file_operations fops_show_read = {
  .owner = THIS_MODULE,
  /** proc 파일이 read될 때 실행 */
  .read = proc_show_read,
};


static const struct file_operations fops_add_write = {
  .owner = THIS_MODULE,
  /** proc 파일이 write될 때 실행 */
  .write = proc_write_add,
};

static const struct file_operations fops_del_write = {
  .owner = THIS_MODULE,
  /** proc 파일이 write될 때 실행 */
  .write = proc_write_del,
};

static int __init firewall_module_init(void) {
  printk(KERN_INFO "Firewall Module Init!!\n");

  /** /proc 디렉터리에 PROC_FILENAME 이름으로 proc 파일 생성 */
  proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
  /** Add */
  proc_file_add = proc_create(PROC_FILENAME_ADD, 0600, proc_dir, &fops_add_write);
  /** Del */
  proc_file_del = proc_create(PROC_FILENAME_DEL, 0600, proc_dir, &fops_del_write);
  /** Show */
  proc_file_show = proc_create(PROC_FILENAME_SHOW, 0600, proc_dir, &fops_show_read);

  /** 메모리 동적 할당*/
  hook_ops_pre = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
  hook_ops_post = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
  hook_ops_forward = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);

  /** PF_INET (IP) */
  hook_ops_pre->pf = PF_INET;
  hook_ops_post->pf = PF_INET;
  hook_ops_forward->pf = PF_INET;

  /** 콜백 함수 등록 */
  hook_ops_pre->hook = (nf_hookfn*)netfilter_hook_func_pre;
  hook_ops_post->hook = (nf_hookfn*)netfilter_hook_func_post;
  hook_ops_forward->hook = (nf_hookfn*)netfilter_hook_func_forward;
  /**
https://elixir.bootlin.com/linux/v4.4/source/include/uapi/linux/netfilter.h#L46
enum nf_inet_hooks {
  NF_INET_PRE_ROUTING,
  NF_INET_LOCAL_IN,
  NF_INET_FORWARD,
  NF_INET_LOCAL_OUT,
  NF_INET_POST_ROUTING,
  NF_INET_NUMHOOKS
};
  */
  hook_ops_pre->hooknum = NF_INET_PRE_ROUTING;
  hook_ops_post->hooknum = NF_INET_POST_ROUTING;
  hook_ops_forward->hooknum = NF_INET_FORWARD;

  /** Set priority */
  hook_ops_pre->priority = NF_IP_PRI_FIRST;
  hook_ops_post->priority = NF_IP_PRI_FIRST;
  hook_ops_forward->priority = NF_IP_PRI_FIRST;

  /** register */
  nf_register_hook(hook_ops_pre);
  nf_register_hook(hook_ops_post);
  nf_register_hook(hook_ops_forward);

  return 0;
}

static void __exit firewall_module_exit(void) {
  printk(KERN_INFO "Firewall Module Exit!!\n");

  /** 모듈이 비활성화될 때 proc 파일 삭제 */
  proc_remove(proc_file_add);
  proc_remove(proc_file_del);
  proc_remove(proc_file_show);
  proc_remove(proc_dir);

  /** unregister */
  nf_unregister_hook(hook_ops_pre);
  nf_unregister_hook(hook_ops_post);
  nf_unregister_hook(hook_ops_forward);

  /** 메모리 할당 해제 */
  kfree(hook_ops_pre);
  kfree(hook_ops_post);
  kfree(hook_ops_forward);
}

/** 이 모듈이 활성화될 때(insmod) 실행 */
module_init(firewall_module_init);
/** 이 모듈이 비활성화될 때(rmmod) 실행 */
module_exit(firewall_module_exit);

MODULE_DESCRIPTION("Firewall");
MODULE_AUTHOR("SP2020 Group 37");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
