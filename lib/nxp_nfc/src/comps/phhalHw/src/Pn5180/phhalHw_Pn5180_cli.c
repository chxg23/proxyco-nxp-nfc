/*
 * @Copyright Proxy Technologies Inc
 */

#include <os/mynewt.h>

#if MYNEWT_VAL(PN5180_CLI)
#include <string.h>
#include <errno.h>
#include "console/console.h"
#include "shell/shell.h"
#include "phhalHw_Pn5180.h"
#include "nxp_nfc/phhalHw_Pn5180_Instr.h"
#include "parse/parse.h"

struct pn5180 *g_shell_pn5180;
extern uint8_t no_hexdump;

static int pn5180_shell_cmd(int argc, char **argv);

static struct shell_cmd pn5180_shell_cmd_struct = {
  .sc_cmd = "pn5180",
  .sc_cmd_func = pn5180_shell_cmd
};

static int
pn5180_shell_err_too_many_args(char *cmd_name)
{
  console_printf("Error: too many arguments for command \"%s\"\n",
      cmd_name);
  return EINVAL;
}

static int
pn5180_shell_err_unknown_arg(char *cmd_name)
{
  console_printf("Error: unknown argument \"%s\"\n",
      cmd_name);
  return EINVAL;
}

static int
pn5180_shell_err_invalid_arg(char *cmd_name)
{
  console_printf("Error: invalid argument \"%s\"\n",
      cmd_name);
  return EINVAL;
}

static int
pn5180_shell_help(void)
{
  console_printf("%s cmd  [flags...]\n", pn5180_shell_cmd_struct.sc_cmd);
  console_printf("cmd:\n");
  console_printf("\treg get [reg]\n");
  console_printf("\treg set [reg value]\n");
  console_printf("\teeprom write [addr data], length is calculated from delimited data\n");
  console_printf("\teeprom read  [addr data length]\n");
  console_printf("\thexdump [0/1]");
  console_printf("\tdump_all\n");
  return 0;
}

static int
pn5180_shell_set_reg(int argc, char **argv)
{
  int rc = 0;
  uint8_t addr;
  uint32_t value;

  if (argc > 5) {
    return pn5180_shell_err_too_many_args(argv[2]);
  }

  addr = parse_ull_bounds(argv[3], 0, 0x25, &rc);
  if (rc) {
    return pn5180_shell_err_invalid_arg(argv[3]);
  }

  value = parse_ull_bounds(argv[4], 0, UINT32_MAX, &rc);
  if (rc) {
    return pn5180_shell_err_invalid_arg(argv[4]);
  }

  return phhalHw_Pn5180_WriteRegister(g_shell_pn5180->data_params, addr, value);
}

static int
pn5180_shell_get_reg(int argc, char **argv)
{
  int rc = 0;
  uint8_t addr;
  uint32_t value;

  if (argc > 4) {
    return pn5180_shell_err_too_many_args(argv[2]);
  }

  addr = parse_ull_bounds(argv[3], 0, 0x25, &rc);
  if (rc) {
    return pn5180_shell_err_invalid_arg(argv[3]);
  }

  rc = phhalHw_Pn5180_ReadRegister(g_shell_pn5180->data_params, addr, &value);
  console_printf("reg: 0x%x value: 0x%x\n", addr, (unsigned int)value);

  return 0;
}

static int
pn5180_shell_hexdump(int argc, char **argv)
{
  int rc = 0;
  uint8_t off;

  if (argc > 3) {
    return pn5180_shell_err_too_many_args(argv[2]);
  }

  off = parse_ull_bounds(argv[2], 0, 1, &rc);

  if (!rc) {
    no_hexdump = (off == 0);
  }

  return 0;
}

static int
pn5180_shell_dump_all(int argc, char **argv)
{
  int rc = 0;
  uint32_t value;
  uint8_t reg_addr = 0;

  for (reg_addr = 0; reg_addr <= 0x25; reg_addr++) {
    rc = phhalHw_Pn5180_ReadRegister(g_shell_pn5180->data_params, reg_addr, &value);
    if (rc) {
      return pn5180_shell_err_invalid_arg(argv[2]);
    }

    console_printf("reg: 0x%x value: 0x%x\n", reg_addr, (unsigned int)value);
  }

  return 0;
}

static int
pn5180_shell_eeprom_write(int argc, char **argv)
{
  int rc = 0;
  uint8_t data[255] = {0};
  int out_len;
  uint8_t addr;

  if (argc > 6) {
    return pn5180_shell_err_too_many_args(argv[2]);
  }

  addr = parse_ull_bounds(argv[3], 0, 254, &rc);
  if (rc) {
    return pn5180_shell_err_invalid_arg(argv[3]);
  }

  rc = parse_byte_stream(argv[4], 255, data, &out_len);
  if (rc) {
    return pn5180_shell_err_invalid_arg(argv[4]);
  }

  return phhalHw_Pn5180_Instr_WriteE2Prom(g_shell_pn5180->data_params, addr, data, out_len);
}

static int
pn5180_shell_eeprom_read(int argc, char **argv)
{
  int rc = 0;
  uint8_t data[255] = {0};
  int out_len;
  uint8_t addr;
  int i = 0;

  if (argc > 5) {
    return pn5180_shell_err_too_many_args(argv[2]);
  }

  addr = parse_ull_bounds(argv[3], 0, 254, &rc);
  if (rc) {
    return pn5180_shell_err_invalid_arg(argv[3]);
  }

  out_len = parse_ull_bounds(argv[4], 1, 255, &rc);
  if (rc) {
    return pn5180_shell_err_invalid_arg(argv[4]);
  }

  rc = phhalHw_Pn5180_Instr_ReadE2Prom(g_shell_pn5180->data_params, addr, data, out_len);
  if (rc) {
    return pn5180_shell_err_invalid_arg(argv[4]);
  }

  console_printf("addr: 0x%x byte stream: ", addr);
  for (i = 0; i < out_len - 1; i++) {
    console_printf("%2x:", data[i]);
  }
  console_printf("%2x\n", data[i]);

  return 0;
}

static int
pn5180_shell_cmd(int argc, char **argv)
{
  if (argc == 1) {
    return pn5180_shell_help();
  }

  if (argc > 1 && strcmp(argv[1], "reg") == 0 && strcmp(argv[2], "set") == 0) {
    return pn5180_shell_set_reg(argc, argv);
  }

  if (argc > 1 && strcmp(argv[1], "reg") == 0 && strcmp(argv[2], "get") == 0) {
    return pn5180_shell_get_reg(argc, argv);
  }

  if (argc > 1 && strcmp(argv[1], "eeprom") == 0 && strcmp(argv[2], "write") == 0) {
    return pn5180_shell_eeprom_write(argc, argv);
  }

  if (argc > 1 && strcmp(argv[1], "eeprom") == 0 && strcmp(argv[2], "read") == 0) {
    return pn5180_shell_eeprom_read(argc, argv);
  }

  if (argc > 1 && strcmp(argv[1], "hexdump") == 0) {
    return pn5180_shell_hexdump(argc, argv);
  }

  if (argc > 1 && strcmp(argv[1], "dump_all") == 0) {
    return pn5180_shell_dump_all(argc, argv);
  }

  return pn5180_shell_err_unknown_arg(argv[1]);
}

void
pn5180_shell_init(void)
{
  int rc;

  rc = shell_cmd_register(&pn5180_shell_cmd_struct);
  SYSINIT_PANIC_ASSERT(rc == 0);

  g_shell_pn5180 = (struct pn5180 *)os_dev_lookup("pn5180_0");

  if (!g_shell_pn5180) {
    console_printf("pn5180 shell init failed!\n");
  }
}

#endif
