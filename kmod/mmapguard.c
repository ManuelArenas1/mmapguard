// SPDX-License-Identifier: GPL-2.0
/*
 * mmapguard - Control de acceso a archivos mapeados con mmap() en la capa de kernel
 *
 * Parcial 25% - Sistemas Operativos 2026-2 (EAFIT)
 *
 * IDEA
 * ----
 * Una vez que una PTE esta presente, leer/escribir una pagina mapeada ocurre a
 * velocidad de hardware SIN pasar por Ring 0. Por eso la unica oportunidad de
 * decidir es cuando se CREA o se CAMBIA el VMA:
 *
 *   mmap()      -> vm_mmap_pgoff() -> security_mmap_file(file, prot, flags)
 *   mprotect()  -> do_mprotect_pkey() -> security_file_mprotect(vma, reqprot, prot)
 *
 * Un LKM no puede registrar un LSM (los LSM son estaticos, se eligen al boot),
 * ni es seguro parchear la sys_call_table (no exportada desde 5.7, CR0.WP
 * "pinned" desde 5.3). Por eso enganchamos esas dos funciones LSM-framework
 * con *kretprobes*: en la entrada inspeccionamos los argumentos (registros) y
 * en el retorno sustituimos el valor de retorno por -EPERM si la politica lo
 * exige. Es exactamente lo que vería un LSM real: el syscall falla con EPERM.
 *
 * POLITICA
 * --------
 *  - Los archivos protegidos se identifican por (s_dev, i_ino), NO por ruta:
 *    resiste symlinks, bind-mounts, rename() y rutas largas (ENAMETOOLONG en
 *    d_path seria un bypass trivial).
 *  - Siempre: se niega  MAP_SHARED + PROT_WRITE   (modificar el archivo via mmap)
 *             y          mprotect() que agregue PROT_WRITE a un VMA compartido
 *                         (el bypass clasico: mapear R/O y luego "subir" a R/W).
 *  - Modo strict: ademas se niega MAP_PRIVATE + PROT_WRITE (COW, vector de
 *             Dirty COW) y cualquier PROT_EXEC sobre el archivo.
 *  - Modos: off | audit (solo registra) | enforce (registra y deniega).
 *
 * INTERFAZ  (/proc/mmapguard, solo root)
 *    cat /proc/mmapguard
 *    echo "mode enforce"  > /proc/mmapguard
 *    echo "strict 1"      > /proc/mmapguard
 *    echo "add /ruta"     > /proc/mmapguard
 *    echo "del /ruta"     > /proc/mmapguard
 *    echo "clear"         > /proc/mmapguard
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Manuel Arenas - Parcial SO 2026-2");
MODULE_DESCRIPTION("Control de mmap()/mprotect() sobre archivos sensibles (kretprobe sobre ganchos LSM)");
MODULE_VERSION("1.0");

/* ------------------------------------------------------------------ */
/* Acceso portable a los argumentos del ABI (x86_64 y arm64)           */
/* ------------------------------------------------------------------ */
#if defined(CONFIG_X86_64)
#define MG_ARG1(r) ((unsigned long)(r)->di)
#define MG_ARG2(r) ((unsigned long)(r)->si)
#define MG_ARG3(r) ((unsigned long)(r)->dx)
#elif defined(CONFIG_ARM64)
#define MG_ARG1(r) ((unsigned long)(r)->regs[0])
#define MG_ARG2(r) ((unsigned long)(r)->regs[1])
#define MG_ARG3(r) ((unsigned long)(r)->regs[2])
#else
#error "mmapguard: arquitectura no soportada (solo x86_64 y arm64)"
#endif

/* ------------------------------------------------------------------ */
/* Parametros / estado                                                 */
/* ------------------------------------------------------------------ */
enum mg_mode { MG_OFF = 0, MG_AUDIT = 1, MG_ENFORCE = 2 };
static const char * const mg_mode_name[] = { "off", "audit", "enforce" };

static int mg_mode   = MG_AUDIT;   /* leido en hot path con READ_ONCE */
static int mg_strict;              /* idem */

static char *mode_param = "audit";
module_param_named(mode, mode_param, charp, 0444);
MODULE_PARM_DESC(mode, "off | audit | enforce (por defecto: audit)");

static bool strict_param;
module_param_named(strict, strict_param, bool, 0444);
MODULE_PARM_DESC(strict, "Tambien negar MAP_PRIVATE+PROT_WRITE y PROT_EXEC (defecto: 0)");

#define MG_MAX_BOOT_PATHS 16
static char *protect[MG_MAX_BOOT_PATHS];
static int nprotect;
module_param_array(protect, charp, &nprotect, 0444);
MODULE_PARM_DESC(protect, "Rutas a proteger desde la carga: protect=/etc/shadow,/ruta2");

/* ------------------------------------------------------------------ */
/* Estadisticas por CPU (sin contencion en el hot path)                */
/* ------------------------------------------------------------------ */
enum {
	S_MMAP_SEEN, S_MMAP_HIT, S_MMAP_DENY,
	S_MPROT_SEEN, S_MPROT_HIT, S_MPROT_DENY,
	S_COW_NOTED, S_MAX
};
struct mg_stats { u64 v[S_MAX]; };
static DEFINE_PER_CPU(struct mg_stats, mg_st);
#define MG_INC(i) this_cpu_inc(mg_st.v[(i)])

/* ------------------------------------------------------------------ */
/* Lista de archivos protegidos (RCU: lectura sin locks en hot path)   */
/* ------------------------------------------------------------------ */
struct mg_entry {
	struct list_head list;
	struct rcu_head  rcu;
	dev_t            dev;
	unsigned long    ino;
	char             path[];   /* solo para mostrar/loguear */
};

static LIST_HEAD(mg_list);
static DEFINE_SPINLOCK(mg_lock);

static struct mg_entry *mg_lookup(const struct inode *inode)
{
	struct mg_entry *e;

	list_for_each_entry_rcu(e, &mg_list, list)
		if (e->ino == inode->i_ino && e->dev == inode->i_sb->s_dev)
			return e;
	return NULL;
}

/* Resuelve ruta -> (dev, ino). Contexto de proceso (puede dormir). */
static int mg_resolve(const char *path, dev_t *dev, unsigned long *ino)
{
	struct path p;
	struct inode *inode;
	int err = kern_path(path, LOOKUP_FOLLOW, &p);

	if (err)
		return err;
	inode = d_backing_inode(p.dentry);
	if (!S_ISREG(inode->i_mode)) {
		path_put(&p);
		return -EINVAL;      /* solo archivos regulares */
	}
	*dev = inode->i_sb->s_dev;
	*ino = inode->i_ino;
	path_put(&p);
	return 0;
}

static int mg_add(const char *path)
{
	struct mg_entry *e;
	dev_t dev;
	unsigned long ino;
	int err = mg_resolve(path, &dev, &ino);

	if (err)
		return err;
	e = kzalloc(sizeof(*e) + strlen(path) + 1, GFP_KERNEL);
	if (!e)
		return -ENOMEM;
	e->dev = dev;
	e->ino = ino;
	strcpy(e->path, path);

	spin_lock(&mg_lock);
	list_add_tail_rcu(&e->list, &mg_list);
	spin_unlock(&mg_lock);
	return 0;
}

static int mg_del(const char *path)
{
	struct mg_entry *e, *tmp;
	dev_t dev;
	unsigned long ino;
	int err = mg_resolve(path, &dev, &ino), found = -ENOENT;

	if (err)
		return err;
	spin_lock(&mg_lock);
	list_for_each_entry_safe(e, tmp, &mg_list, list) {
		if (e->dev == dev && e->ino == ino) {
			list_del_rcu(&e->list);
			kfree_rcu(e, rcu);
			found = 0;
		}
	}
	spin_unlock(&mg_lock);
	return found;
}

static void mg_clear(void)
{
	struct mg_entry *e, *tmp;

	spin_lock(&mg_lock);
	list_for_each_entry_safe(e, tmp, &mg_list, list) {
		list_del_rcu(&e->list);
		kfree_rcu(e, rcu);
	}
	spin_unlock(&mg_lock);
}

/* ------------------------------------------------------------------ */
/* Motor de decision (comun a mmap y mprotect)                         */
/* ------------------------------------------------------------------ */
enum mg_reason { R_NONE, R_SHARED_WRITE, R_PRIVATE_WRITE, R_EXEC };
static const char * const mg_reason_str[] = {
	"ok", "shared-write", "private-write(cow)", "exec"
};

/* Devuelve el errno a imponer (0 = permitir) y registra la auditoria. */
static int mg_evaluate(const char *op, struct file *file,
		       unsigned long prot, bool shared, int hit_stat, int deny_stat)
{
	struct mg_entry *e;
	int reason = R_NONE, mode = READ_ONCE(mg_mode);
	int strict = READ_ONCE(mg_strict), err = 0;

	rcu_read_lock();
	e = mg_lookup(file_inode(file));
	if (!e)
		goto out;
	MG_INC(hit_stat);

	if ((prot & PROT_WRITE) && shared)
		reason = R_SHARED_WRITE;
	else if ((prot & PROT_WRITE) && !shared) {
		MG_INC(S_COW_NOTED);              /* siempre lo contamos */
		if (strict)
			reason = R_PRIVATE_WRITE;
	} else if ((prot & PROT_EXEC) && strict)
		reason = R_EXEC;
	if (reason == R_NONE)
		goto out;

	if (mode == MG_ENFORCE) {
		err = EPERM;
		MG_INC(deny_stat);
	}
	pr_warn_ratelimited("%s %s: pid=%d comm=%s uid=%u file=%s motivo=%s prot=%c%c%c %s\n",
			    mg_mode_name[mode], op, task_pid_nr(current), current->comm,
			    from_kuid(&init_user_ns, current_uid()), e->path,
			    mg_reason_str[reason],
			    (prot & PROT_READ) ? 'r' : '-',
			    (prot & PROT_WRITE) ? 'w' : '-',
			    (prot & PROT_EXEC) ? 'x' : '-',
			    shared ? "SHARED" : "PRIVATE");
out:
	rcu_read_unlock();
	return err;
}

/* ------------------------------------------------------------------ */
/* kretprobe 1: security_mmap_file(file, prot, flags)                  */
/* ------------------------------------------------------------------ */
struct mg_ri { int err; };

static int mmap_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mg_ri *d = (struct mg_ri *)ri->data;
	struct file *file = (struct file *)MG_ARG1(regs);
	unsigned long prot = MG_ARG2(regs), flags = MG_ARG3(regs);

	d->err = 0;
	MG_INC(S_MMAP_SEEN);
	if (!file || READ_ONCE(mg_mode) == MG_OFF)
		return 0;
	/* MAP_SHARED (1) y MAP_SHARED_VALIDATE (3) son compartidos */
	d->err = mg_evaluate("mmap", file, prot,
			     (flags & MAP_TYPE) != MAP_PRIVATE,
			     S_MMAP_HIT, S_MMAP_DENY);
	return 0;
}

static int mmap_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mg_ri *d = (struct mg_ri *)ri->data;

	/* Solo sobrescribimos si el sistema habria permitido la operacion */
	if (d->err && regs_return_value(regs) == 0)
		regs_set_return_value(regs, -d->err);
	return 0;
}

/* ------------------------------------------------------------------ */
/* kretprobe 2: security_file_mprotect(vma, reqprot, prot)             */
/* ------------------------------------------------------------------ */
static int mprot_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mg_ri *d = (struct mg_ri *)ri->data;
	struct vm_area_struct *vma = (struct vm_area_struct *)MG_ARG1(regs);
	unsigned long prot = MG_ARG3(regs);   /* prot efectivo (tras READ_IMPLIES_EXEC) */

	d->err = 0;
	MG_INC(S_MPROT_SEEN);
	if (!vma || !vma->vm_file || READ_ONCE(mg_mode) == MG_OFF)
		return 0;
	d->err = mg_evaluate("mprotect", vma->vm_file, prot,
			     !!(vma->vm_flags & VM_SHARED),
			     S_MPROT_HIT, S_MPROT_DENY);
	return 0;
}

static struct kretprobe krp_mmap = {
	.kp.symbol_name = "security_mmap_file",
	.entry_handler  = mmap_entry,
	.handler        = mmap_ret,
	.data_size      = sizeof(struct mg_ri),
	.maxactive      = 256,
};

static struct kretprobe krp_mprot = {
	.kp.symbol_name = "security_file_mprotect",
	.entry_handler  = mprot_entry,
	.handler        = mmap_ret,        /* misma logica de retorno */
	.data_size      = sizeof(struct mg_ri),
	.maxactive      = 256,
};

/* ------------------------------------------------------------------ */
/* /proc/mmapguard                                                     */
/* ------------------------------------------------------------------ */
static u64 mg_sum(int idx)
{
	u64 s = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		s += per_cpu(mg_st, cpu).v[idx];
	return s;
}

static int mg_show(struct seq_file *m, void *v)
{
	struct mg_entry *e;

	seq_printf(m, "mode:    %s\nstrict:  %d\n",
		   mg_mode_name[READ_ONCE(mg_mode)], READ_ONCE(mg_strict));
	seq_printf(m, "mmap:     vistas=%llu protegidas=%llu denegadas=%llu\n",
		   mg_sum(S_MMAP_SEEN), mg_sum(S_MMAP_HIT), mg_sum(S_MMAP_DENY));
	seq_printf(m, "mprotect: vistas=%llu protegidas=%llu denegadas=%llu\n",
		   mg_sum(S_MPROT_SEEN), mg_sum(S_MPROT_HIT), mg_sum(S_MPROT_DENY));
	seq_printf(m, "mapeos privados escribibles (COW) observados: %llu\n",
		   mg_sum(S_COW_NOTED));
	seq_puts(m, "protegidos:\n");
	rcu_read_lock();
	list_for_each_entry_rcu(e, &mg_list, list)
		seq_printf(m, "  dev=%u:%u ino=%lu  %s\n",
			   MAJOR(e->dev), MINOR(e->dev), e->ino, e->path);
	rcu_read_unlock();
	return 0;
}

static int mg_open(struct inode *inode, struct file *file)
{
	return single_open(file, mg_show, NULL);
}

static ssize_t mg_write(struct file *file, const char __user *ubuf,
			size_t len, loff_t *off)
{
	char *buf, *arg, *cmd;
	int i, err = -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (len == 0 || len >= PATH_MAX + 16)
		return -EINVAL;
	/* La pila del kernel es de 8-16 KB: nada de buffers PATH_MAX en ella */
	buf = memdup_user_nul(ubuf, len);
	if (IS_ERR(buf))
		return PTR_ERR(buf);
	cmd = strim(buf);
	arg = strchr(cmd, ' ');
	if (arg) {
		*arg++ = '\0';
		arg = strim(arg);
	}

	if (!strcmp(cmd, "mode") && arg) {
		for (i = 0; i < ARRAY_SIZE(mg_mode_name); i++)
			if (!strcmp(arg, mg_mode_name[i])) {
				WRITE_ONCE(mg_mode, i);
				err = 0;
			}
	} else if (!strcmp(cmd, "strict") && arg) {
		WRITE_ONCE(mg_strict, arg[0] == '1');
		err = 0;
	} else if (!strcmp(cmd, "add") && arg) {
		err = mg_add(arg);
	} else if (!strcmp(cmd, "del") && arg) {
		err = mg_del(arg);
	} else if (!strcmp(cmd, "clear")) {
		mg_clear();
		err = 0;
	}
	kfree(buf);
	return err ? err : len;
}

static const struct proc_ops mg_proc_ops = {
	.proc_open    = mg_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = mg_write,
};

/* ------------------------------------------------------------------ */
/* init / exit                                                         */
/* ------------------------------------------------------------------ */
static int __init mg_init(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(mg_mode_name); i++)
		if (!strcmp(mode_param, mg_mode_name[i]))
			mg_mode = i;
	mg_strict = strict_param;

	if (!proc_create("mmapguard", 0600, NULL, &mg_proc_ops))
		return -ENOMEM;

	for (i = 0; i < nprotect; i++) {
		ret = mg_add(protect[i]);
		if (ret)
			pr_warn("no se pudo proteger '%s' (err=%d)\n", protect[i], ret);
	}

	ret = register_kretprobe(&krp_mmap);
	if (ret < 0) {
		pr_err("register_kretprobe(security_mmap_file) fallo: %d "
		       "(CONFIG_SECURITY/CONFIG_KPROBES activos?)\n", ret);
		goto err_proc;
	}
	ret = register_kretprobe(&krp_mprot);
	if (ret < 0) {
		pr_err("register_kretprobe(security_file_mprotect) fallo: %d\n", ret);
		goto err_mmap;
	}
	pr_info("cargado: modo=%s strict=%d archivos=%d\n",
		mg_mode_name[mg_mode], mg_strict, nprotect);
	return 0;

err_mmap:
	unregister_kretprobe(&krp_mmap);
err_proc:
	remove_proc_entry("mmapguard", NULL);
	mg_clear();
	return ret;
}

static void __exit mg_exit(void)
{
	/* unregister espera a que terminen los handlers en vuelo */
	unregister_kretprobe(&krp_mprot);
	unregister_kretprobe(&krp_mmap);
	remove_proc_entry("mmapguard", NULL);
	mg_clear();
	rcu_barrier();                       /* kfree_rcu pendientes antes de descargar */
	pr_info("descargado (mmap denegados=%llu, mprotect denegados=%llu)\n",
		mg_sum(S_MMAP_DENY), mg_sum(S_MPROT_DENY));
}

module_init(mg_init);
module_exit(mg_exit);
