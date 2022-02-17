#include <linux/yama_rust_c_exports.h>
#include <linux/rcupdate.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/sched/task.h>
#include <linux/ptrace.h>
#include <linux/sched/signal.h>
#include <linux/user_namespace.h>

void rcu_read_lock_exported() {
    rcu_read_lock();
}

void rcu_read_unlock_exported() {
    rcu_read_unlock();
}

int ns_capable_exported(struct user_namespace *ns, int cap) {
    return (int)(ns_capable(ns, cap));
}

const struct cred *__task_cred_exported(struct task_struct *task) {
    return __task_cred(task);
}

void *rcu_dereference_exported(void **p) {
    return rcu_dereference(*p);
}

void rcu_assign_pointer_exported(void **p, void *v) {
    rcu_assign_pointer(*p, v);
}

struct task_struct *get_current_exported() {
    return get_current();
}

struct task_struct *get_task_struct_exported(struct task_struct *t) {
    return get_task_struct(t);
}

void put_task_struct_exported(struct task_struct *t) {
    put_task_struct(t);
}

struct task_struct *ptrace_parent_exported(struct task_struct *t) {
    return ptrace_parent(t);
}

bool same_thread_group_exported(struct task_struct *p1, struct task_struct *p2) {
    return same_thread_group(p1, p2);
}

struct user_namespace *current_user_ns_exported(void) {
    return current_user_ns();
}