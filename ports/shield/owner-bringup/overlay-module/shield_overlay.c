// Generic runtime DT overlay loader for the Shield port. Loads one reviewed overlay
// from the firmware search path, guarded by a node that must currently be disabled.
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/of.h>
#define MAX_OVERLAYS 4
static char *overlay_path[MAX_OVERLAYS];
static int n_paths;
module_param_array(overlay_path, charp, &n_paths, 0400);
MODULE_PARM_DESC(overlay_path, "firmware-relative DT overlays (.dtbo), comma separated");
static char *guard_node[MAX_OVERLAYS];
static int n_guards;
module_param_array(guard_node, charp, &n_guards, 0400);
MODULE_PARM_DESC(guard_node, "DT node paths that must exist and be disabled, one per overlay");
static int overlay_id[MAX_OVERLAYS];
static int n_applied;
static int apply_one(const char *path, const char *guard, int *id)
{
	const struct firmware *fw;
	struct device_node *node;
	int ret;
	node = of_find_node_by_path(guard);
	if (!node)
		return -ENODEV;
	if (of_device_is_available(node)) {
		of_node_put(node);
		return -EBUSY;
	}
	of_node_put(node);
	ret = request_firmware(&fw, path, NULL);
	if (ret)
		return ret;
	ret = of_overlay_fdt_apply(fw->data, fw->size, id, NULL);
	release_firmware(fw);
	if (ret && *id) {
		int rollback = of_overlay_remove(id);
		if (rollback)
			pr_err("shield_overlay: rollback failed: %d\n", rollback);
	}
	pr_info("shield_overlay: %s on %s -> %d\n", path, guard, ret);
	return ret;
}
static int __init shield_overlay_init(void)
{
	int i, ret;
	if (n_paths < 1 || n_paths != n_guards)
		return -EINVAL;
	for (i = 0; i < n_paths; i++) {
		if (!overlay_path[i] || !*overlay_path[i] || !guard_node[i] || !*guard_node[i])
			return -EINVAL;
		ret = apply_one(overlay_path[i], guard_node[i], &overlay_id[i]);
		if (ret) {
			while (n_applied > 0) {
				n_applied--;
				of_overlay_remove(&overlay_id[n_applied]);
			}
			return ret;
		}
		n_applied++;
	}
	return 0;
}
static void __exit shield_overlay_exit(void)
{
	while (n_applied > 0) {
		int ret;
		n_applied--;
		ret = of_overlay_remove(&overlay_id[n_applied]);
		if (ret)
			pr_err("shield_overlay: overlay remove failed: %d\n", ret);
	}
}
module_init(shield_overlay_init);
module_exit(shield_overlay_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Runtime Shield DT overlay enablement");
