# sp2020-assignment

## 소스코드에 대한 설명

### 1. module_init 및 module_exit 부분

LKM이 초기화되는 부분(`firewall_module_init`)에서는 다음과 같은 작업이 수행됩니다. 먼저 add, del, show에 대한 작업을 할 수 있도록 proc directory와 proc file을 `proc_mkdir`와 `proc_create` 함수로 생성합니다. 그 후, PREROUTING, POSTROUTING, FORWARD에 대한 Netfilter 후킹을 수행하기 위한 정보를 담는 구조체인 `nf_hook_ops` 구조체를 초기화합니다. 이 때, `nf_hook_ops` 구조체에 대한 메모리를 동적으로 할당해야 하는데, 이는 `kmalloc` 함수를 이용하여 커널 스페이스에 메모리를 동적으로 할당합니다. 그 후, 각 hook_ops 구조체에 `pf`, `hook`, `hooknum`, `priority` 프로퍼티를 할당합니다. `pf`의 경우에는 IP에 대한 후킹을 수행한다는 의미인 `PF_INET` 값을 할당하였고, `hook`에는 각각의 후킹 유형에 맞는 콜백 함수 포인터를 할당하였습니다. `hooknum`의 경우에는 후킹 유형에 따라 알맞은 `nf_inet_hooks` enumerator를 할당해 주어야 합니다. 이 경우에는 각각 `NF_INET_PRE_ROUTING`, `NF_INET_POST_ROUTING`, `NF_INET_FORWARD`를 할당해 주었습니다. `priority`에는 이 hook_ops에 대한 실행 우선순위를 지정할 수 있는데, 높은 우선순위를 의미하는 `NF_IP_PRI_FIRST`를 할당해 주었습니다. 할당이 끝난 hook_ops 구조체들은 각각 `nf_register_hook` 함수를 이용하여 커널에 등록해 주었습니다.

LKM이 비활성화되는 부분(`firewall_module_exit`)에서는 다음과 같은 작업을 수행합니다. 먼저 `proc_remove` 함수를 이용하여 더이상 사용되지 않는 proc file들을 제거해 줍니다. 그 후, `nf_unregister_hook` 함수를 이용하여 각각의 hook_ops를 커널에서부터 등록 해제합니다. 사용되지 않는 각 hook_ops는 `kfree` 함수를 이용하여 메모리 할당을 해제하고, null 포인터를 할당합니다.


### 2. Netfilter Hook 함수 (netfilter_hook_func)

`nf_register_hook`으로 등록된 각각의 `nf_hook_ops`는 `hook` property에 들어있는 함수 포인터를 콜백 함수로 실행합니다. 각각의 콜백 함수는 바로 `_netfilter_hook_func` 함수를 실행하고, 이 함수 내에서 실제 Hook operation을 실행합니다. `_netfilter_hook_func`에 실제 로직을 넣음으로서 중복되는 코드를 줄일 수 있었습니다. `_netfilter_hook_func` 함수를 호출할 때, `rule_type`을 넣어주는데 이에 대한 규칙은 다음과 같습니다.
- `NF_INET_PRE_ROUTING`의 경우, Inbound traffic을 의미하는 'I'
- `NF_INET_POST_ROUTING`의 경우, Outbound traffic을 의미하는 'O'
- `NF_INET_FORWARD`의 경우, Forward traffic을 의미하는 'F'
이에 따라 `_netfilter_hook_func` 함수에서는 각 트래픽의 전달 방향(direction 변수)을 표시해 줍니다.

`_netfilter_hook_func` 함수에서는 실제 Hook에 대한 로직을 실행합니다. socket buffer(`sk_buff* skb`)로부터 IP header 정보와 TCP header 정보를 추출하는데, 이는 각각 `ip_hdr`와 `tcp_hdr` 함수를 이용하여 추출할 수 있었습니다. TCP/IP header 정보를 추출한 이후에는 IP source / destination address, TCP source / destination port 값을 받아올 수 있었습니다. IP 주소는 실습자료에서 주어진 `as_net_to_addr` 함수를 통해 IP header에서 x.x.x.x 형태의 문자열로 추출할 수 있었습니다. TCP port 번호는 네트워크에서 사용되는 byte order와 호스트에서 사용되는 byte order가 서로 다르기 때문에, byte order를 서로의 규칙대로 변경해주는 `ntohs`, `htons` 함수를 사용하였습니다. 각각의 IP 주소와 port 번호를 추출한 뒤에는 해당 포트 번호가 I(Inbound), O(Outbound), F(Forward) Drop 규칙을 가지고 있는지를 `is_in_netfilter_rules` 함수를 통해 확인합니다. 만약 해당 포트번호에 맞는 규칙이 있다면, Drop이 되었다는 사실을 `printk` 함수로 로깅 후 해당 패킷을 Drop함을 의미하는 `NF_DROP`을 리턴합니다. 그 외의 경우에는 해당 패킷을 통과시킴을 의미하는 `NF_ACCEPT`를 리턴합니다.
Inbound, Outbound, Forward 트래픽마다 각각 확인해야하는 포트 번호가 다른데, Inbound 트래픽의 경우에는 서버에서 클라이언트로 '들어오는' 트래픽이기 때문에 source port를 확인해야 합니다. Outbound와 Forward 트래픽의 경우에는 '나가는' 트래픽이기 때문에 destination port를 확인합니다. TCP가 아닌 경우(UDP 등)와 각각의 추출 루틴이 실패하는 경우에는 예외처리를 하여 NF_ACCEPT를 리턴하도록 프로그래밍하였습니다.
포트 번호가 Proxy rule에 맞는 경우에는 해당 패킷의 destination IP 주소와 TCP 포트 번호를 변경해 주어야 합니다. destination IP 주소는 '131.1.1.1' 주소를 `in_aton` 함수를 통해 ip header에서 사용하는 정수값으로 변경하여 줍니다. TCP 포트 번호는 위에서 언급한 `htons` 함수를 통해 source 포트 번호로 변경해 줍니다. 그 후, IP header의 checksum을 invalidate 후 다시 계산해 주는 `ip_send_check` 함수를 호출해주고, Proxy가 되었다는 사실을 로깅 후 해당 패킷을 Accept 해줍니다.

### 3. proc file read / write 처리 부분 (proc_show_read, proc_write_*)

방화벽 rule을 관리하는 부분은 `list_head` 구조체를 이용한 doubly linked list로 이루어져 있습니다. 이 부분은 `netfilter_rule` 구조체로 선언하였고, 실제로 방화벽 rule이 저장되는 부분은 `rules`라는 변수에 정적으로 선언 및 할당해 주었습니다. 이 때 `list_head` 구조체를 정적으로 할당할 수 있는 `LIST_HEAD_INIT` 매크로 함수를 사용해 주었습니다.
Proc file을 통해 각각의 rule을 처리하는 부분은 `proc_show_read`와 `proc_write_(add|del)` 함수에서 처리합니다. `proc_show_read` 함수에서는 1차과제와 동일한 패턴으로 유저가 읽을 수 있는 string buffer를 만들어 주는데, 이 때 rules에 저장된 rule을 순회하기 위하여 `list_for_each_entry` 매크로 함수를 사용하였습니다. 위에서 언급한 `is_in_netfilter_rules` 함수 또한 `list_for_each_entry` 매크로 함수를 이용하여 rules를 순회합니다.
Proc file을 이용하여 rule을 추가 / 삭제하는 부분은 `proc_write_add`와 `proc_write_del` 함수를 이용하여 처리합니다. 코드 중복을 줄이기 위하여 (2)와 유사한 패턴으로 `_proc_write` 함수를 이어서 호출하고, `_proc_write` 함수에서 실제 rule을 추가 / 삭제하는 `add_netfilter_rules`와 `remove_netfilter_rules` 함수를 호출합니다. `add_netfilter_rules` 함수에서는 현재 rules의 가장 끝 linked list entry를 가져와 새로운 rule(`new_rule` 변수)을 붙여줍니다. 이 때, 가장 끝 entry를 가져오기 위하여 `list_last_entry` 매크로 함수를 사용하였습니다. `new_rule`의 경우에도 rule의 list를 초기화해 주어야 하는데, 이 경우에는 `list_head` 구조체를 동적으로 초기화할 수 있는 `INIT_LIST_HEAD` 매크로 함수를 사용하였습니다. `remove_netfilter_rules` 함수에서는 사용하지 않는 rule을 삭제하는 로직을 구현해 두었습니다. 다만, 이 경우 실제 linked list에서 삭제할 rule entry를 직접 지우지 않고, `netfilter_rule` 구조체에 직접 선언한 `is_active` flag를 0으로 변경해 주었습니다. `is_active` flag가 0인 entry는 다른 로직에서 없는 rule과 마찬가지로 취급이 됩니다.

