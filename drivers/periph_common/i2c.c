/*
 * Copyright (C) 2018 Mesotic SAS <dylan.laduranty@mesotic.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for more
 * details.
 */

/**
 * @ingroup     drivers_periph_i2c
 * @{
 *
 * @file
 * @brief       common I2C function fallback implementations
 *
 * @author      Dylan Laduranty <dylan.laduranty@mesotic.com>
 *
 * @}
 */
#include <errno.h>

#include "board.h"
#include "cpu.h"
#include "periph/i2c.h"
#include "byteorder.h"

#ifdef I2C_NUMOF

#ifdef PERIPH_I2C_NEED_READ_REG
int i2c_read_reg(i2c_t dev, uint16_t addr, uint16_t reg,
                 void *data, uint8_t flags)
{
    return i2c_read_regs(dev, addr, reg, data, 1, flags);
}
#endif /* PERIPH_I2C_NEED_READ_REG */

#ifdef PERIPH_I2C_NEED_READ_REGS
int i2c_read_regs(i2c_t dev, uint16_t addr, uint16_t reg,
                  void *data, size_t len, uint8_t flags)
{
    uint16_t reg_end = reg;

    if (flags & (I2C_NOSTOP | I2C_NOSTART)) {
        return -EOPNOTSUPP;
    }

    /* Handle endianess of register if 16 bit */
    if (flags & I2C_REG16) {
        reg_end = htons(reg); /* Make sure register is in big-endian on I2C bus */
    }

    /* First set ADDR and register with no stop */
    int ret = i2c_write_bytes(dev, addr, &reg_end, (flags & I2C_REG16) ? 2 : 1,
                              flags | I2C_NOSTOP);
    if (ret < 0) {
        return ret;
    }
    /* Then get the data from device */
    return i2c_read_bytes(dev, addr, data, len, flags);
}
#endif /* PERIPH_I2C_NEED_READ_REGS */

int i2c_read_byte(i2c_t dev, uint16_t addr, void *data, uint8_t flags)
{
    return i2c_read_bytes(dev, addr, data, 1, flags);
}

int i2c_write_byte(i2c_t dev, uint16_t addr, uint8_t data, uint8_t flags)
{
    return i2c_write_bytes(dev, addr, &data, 1, flags);
}

#ifdef PERIPH_I2C_NEED_WRITE_REG
int i2c_write_reg(i2c_t dev, uint16_t addr, uint16_t reg,
                  uint8_t data, uint8_t flags)
{
    return i2c_write_regs(dev, addr, reg, &data, 1, flags);
}
#endif /* PERIPH_I2C_NEED_WRITE_REG */

#ifdef PERIPH_I2C_NEED_WRITE_REGS
int i2c_write_regs(i2c_t dev, uint16_t addr, uint16_t reg,
                   const void *data, size_t len, uint8_t flags)
{
    uint16_t reg_end = reg;

    if (flags & (I2C_NOSTOP | I2C_NOSTART)) {
        return -EOPNOTSUPP;
    }

    /* Handle endianess of register if 16 bit */
    if (flags & I2C_REG16) {
        reg_end = htons(reg); /* Make sure register is in big-endian on I2C bus */
    }

    /* First set ADDR and register with no stop */
    int ret = i2c_write_bytes(dev, addr, &reg_end, (flags & I2C_REG16) ? 2 : 1,
                              flags | I2C_NOSTOP);
    if (ret < 0) {
        return ret;
    }
    /* Then write data to the device */
    return i2c_write_bytes(dev, addr, data, len, flags | I2C_NOSTART);
}
#endif /* PERIPH_I2C_NEED_WRITE_REGS */


i2c_slave_fsm_t *i2c_slave_fsm = NULL;

void i2c_slave_reset_fsm(i2c_slave_fsm_t *fsm)
{
  fsm->reg_addr = 0;
  fsm->state = I2C_SLAVE_STATE_IDLE;
  fsm->data = NULL;
  fsm->len = 0;
  fsm->index = 0;
}

void i2c_slave_reg_clear(void)
{
  i2c_slave_fsm = NULL;
}

void i2c_slave_reg(i2c_slave_fsm_t *fsm, i2c_salve_prepare_callback_t prepare, i2c_salve_finish_callback_t finish, uint8_t flags, void *arg)
{
  i2c_slave_reset_fsm(fsm);
  fsm->prepare = prepare;
  fsm->finish = finish;
  fsm->flags = flags;
  fsm->arg = arg;

  i2c_slave_fsm = fsm;
}

#endif /* I2C_NUMOF */
