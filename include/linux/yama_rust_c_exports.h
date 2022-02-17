#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/user_namespace.h>

void rcu_read_lock_exported(void);
void rcu_read_unlock_exported(void);
int ns_capable_exported(struct user_namespace *ns, int cap);
const struct cred *__task_cred_exported(struct task_struct *task);
void *rcu_dereference_exported(void **p);
void rcu_assign_pointer_exported(void **p, void *v);
struct task_struct *get_current_exported(void);
struct task_struct *get_task_struct_exported(struct task_struct *t);
void put_task_struct_exported(struct task_struct *t);
struct task_struct *ptrace_parent_exported(struct task_struct *t);
bool same_thread_group_exported(struct task_struct *p1, struct task_struct *p2);
struct user_namespace *current_user_ns_exported(void);