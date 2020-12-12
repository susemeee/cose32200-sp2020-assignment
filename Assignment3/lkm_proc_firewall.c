#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <asm/uaccess.h>


#define NETFILTER_RULES_MAX_LENGTH 1000

#define PROC_DIRNAME "groupx"
#define PROC_FILENAME_ADD "add"
#define PROC_FILENAME_DEL "del"
#define PROC_FILENAME_SHOW "show"

static struct proc_dir_entry* proc_dir;
static struct proc_dir_entry* proc_file_add;
static struct proc_dir_entry* proc_file_del;
static struct proc_dir_entry* proc_file_show;

unsigned int as_addr_to_net(char *str) {
  unsigned char arr[4]; sscanf(str, "%d.%d.%d.%d", &arr[0], &arr[1], &arr[2], &arr[3]);
  return *(unsigned int *)arr;
}

char *as_net_to_addr(unsigned int addr, char str[]) {
  char add[16];
  unsigned char a = ((unsigned char *)&addr)[0];
  unsigned char b = ((unsigned char *)&addr)[1];
  unsigned char c = ((unsigned char *)&addr)[2];
  unsigned char d = ((unsigned char *)&addr)[3];
  sprintf(add, "%u.%u.%u.%u", a, b, c, d); sprintf(str, "%s", add);
  return str;
}

enum PROC_WRITE_TYPE {
  ADD,
  DEL,
};

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

  char* direction = skb->pkt_type == PACKET_OUTGOING ? "OUTBOUND" : "INBOUND";
  char* saddr = as_net_to_addr(ntohs(ip_header->saddr));
  char* daddr = as_net_to_addr(ntohs(ip_header->daddr));

  /** TCP가 아닌 경우 */
  if (ip_header->protocol != IPPROTO_TCP) {
    return NF_ACCEPT;
  }

  struct tcphdr* tcp_header = tcp_hdr(skb);

  if (tcp_header == NULL) {
    printk(KERN_WARNING "_netfilter_hook_func: tcp_header is null!");
    return NF_ACCEPT;
  }

  int sport = ntohs(tcphdr->src);
  int dport = ntohs(tcphdr->dest);
  int syn = tcp_header->th_flags & TH_SYN;
  int fin = tcp_header->th_flags & TH_FIN;
  int ack = tcp_header->th_flags & TH_ACK;
  int rst = tcp_header->th_flags & TH_RST;


  if (is_in_netfilter_rules(rule_type, dport)) {
    /** type, protocol, sport, dport, saddr, daddr, tcp bit */
    printk(KERN_INFO "DROP[%8s]: %d, %d, %d, %d, %d, %d%d%d%d", direction, ip_header->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);
    return NF_DROP;
  }

  /** proxy */
  if (is_in_netfilter_rules('P', dport)) {
    ip_header->daddr = htons(as_addr_to_net("131.1.1.1"));
    tcp_header->dest = tcp_header->src;
    printk(KERN_INFO "PROXY[%8s]: %d, %d, %d, %d, %d, %d%d%d%d", direction, ip_header->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);
    return NF_ACCEPT;
  }

  /** type, protocol, sport, dport, saddr, daddr, tcp bit */
  printk(KERN_INFO "[%8s]: %d, %d, %d, %d, %d, %d%d%d%d", direction, ip_header->protocol, sport, dport, saddr, daddr, syn, fin, ack, rst);
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

typedef struct {
  /** index */
  int index;
  /** IOFP */
  char rule_type;
  /** 포트 번호 */
  int port;
  /** is_active */
  int is_active;
} netfilter_rule;

static netfilter_rule rules[NETFILTER_RULES_MAX_LENGTH];

static int is_in_netfilter_rules(char rule_type, int port) {
  for (int i = 0; i < NETFILTER_RULES_MAX_LENGTH; i++) {
    if (rules[i].is_active == 1 && rules[i].rule_type == rule_type && rules[i].port == port) {
      return 1;
    }
  }
  return 0;
}

static int add_netfilter_rules(char rule_type, int port) {

  if (rule_type != 'I' && rule_type != 'O' && rule_type != 'P' && rule_type != 'F') {
    printk(KERN_WARNING "add_netfilter_rules: Invalid rule type. Must be one of I, O, P, F.");
    return -1;
  }

  int i = 0;
  while (rules[i].is_active == 1) {
    i++;
  }
  rules[i] = {
    .index = i,
    .rule_type = rule_type,
    .port = port,
    .is_active = 1,
  };

  return i;
}

/**
 * 특정 index의 Netfilter rule을 비활성화하는 함수
 */
static int remove_netfilter_rules(int index) {
  if (rules[i].is_active == 1) {
    rules[i].is_active = 0;
    return 0;
  } else {
    return -1;
  }
}


static ssize_t _proc_write(PROC_WRITE_TYPE type, struct file* file, const char __user* user_buffer, size_t count, loff_t* ppos) {
  return -1;
}


static ssize_t proc_write_add(struct file* file, const char __user* user_buffer, size_t count, loff_t* ppos) {
  printk(KERN_INFO "Firewall Module Add!!\n");
  return _proc_write(PROC_WRITE_TYPE.ADD, file, user_buffer, count, ppos);
}

static ssize_t proc_write_del(struct file* file, const char __user* user_buffer, size_t count, loff_t* ppos) {
  printk(KERN_INFO "Firewall Module Del!!\n");
  return _proc_write(PROC_WRITE_TYPE.DEL, file, user_buffer, count, ppos);
}

/**
 * proc 파일이 read (e.g. cat /proc/PROC_FILENAME) 될 때 실행되는 부분.
 * user space에서는 리턴값(buffer_length)만큼 user_buffer를 읽음.
 */
static ssize_t proc_show_read(struct file* file, char __user* user_buffer, size_t count, loff_t* ppos) {

  int buffer_length = 0;
  printk(KERN_INFO "procfile_read (/proc/%s) called\n", PROC_FILENAME);

  if (*ppos > 0 || count < BUFFER_SIZE) {
    // user가 처음 read를 한 케이스가 아니거나(ppos > 0), read count가 buffer size보다 작을 경우, EOF(0)를 리턴한다.
    return 0;
  } else {

    int i = 0;
    do {
      netfilter_rule rule = rules[i];
      if (rule.is_active == 1) {
        buffer_length += sprintf(buffer + buffer_length, "%d(%c): %d\n", rule.index, rule.rule_type, .port);
      }
    } while (rules[i].index != -1);

    // kernel -> user space로 buffer를 복사한다. 실패할 경우 segfault
    if (buffer_length > 0 && copy_to_user(user_buffer, buffer, buffer_length)) {
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
  hook_ops_pre = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops));
  hook_ops_post = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops));
  hook_ops_forward = (struct nf_hook_ops*)kmalloc(sizeof(struct nf_hook_ops));

  /** 콜백 함수 등록 */
  hook_ops_pre->hook = (nf_hook_fn*)netfilter_hook_func_pre;
  hook_ops_post->hook = (nf_hook_fn*)netfilter_hook_func_post;
  hook_ops_forward->hook = (nf_hook_fn*)netfilter_hook_func_forward;
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

  /** register */
  nf_register_net_hook(&init_net, hook_ops_pre);
  nf_register_net_hook(&init_net, hook_ops_post);
  nf_register_net_hook(&init_net, hook_ops_forward);

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
  nf_unregister_net_hook(&init_net, hook_ops_pre);
  nf_unregister_net_hook(&init_net, hook_ops_post);
  nf_unregister_net_hook(&init_net, hook_ops_forward);

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
MODULE_AUTHOR("SP2020 Group");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
