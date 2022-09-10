#define _GNU_SOURCE
#include "liburing/io_uring.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

const size_t BUF_SIZE = 65535;

int tun_alloc(char *dev) {
  struct ifreq ifr;
  int fd, err;
  if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0)
    return fd;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE;
  if (*dev)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return err;
  }
  return fd;
}

struct user_data {
  bool read;
  size_t index;
};

static void queue_read(struct io_uring *ring, int fd, struct user_data *data,
                       struct iovec *iov, size_t i) {
  struct io_uring_sqe *sqe;
  sqe = io_uring_get_sqe(ring);
  io_uring_prep_read_fixed(sqe, fd, iov[i].iov_base, iov[i].iov_len, 0, i);
  sqe->flags |= IOSQE_FIXED_FILE;
  data->read = true;
  data->index = i;
  io_uring_sqe_set_data(sqe, data);
  io_uring_submit(ring);
}

void *run(void *files) {
  struct io_uring ring;
  struct io_uring_params params;

  memset(&params, 0, sizeof(params));
  params.flags |= IORING_SETUP_SQPOLL;
  params.sq_thread_idle = 2000;

  assert(!io_uring_queue_init_params(128, &ring, &params));

  struct iovec iov[2];
  for (int i = 0; i < 2; i++) {
    iov[i].iov_base = malloc(BUF_SIZE);
    iov[i].iov_len = BUF_SIZE;
  }
  assert(!io_uring_register_buffers(&ring, iov, 2));

  assert(!io_uring_register_files(&ring, files, 2));

  struct user_data datas_write[2];
  struct user_data datas_read[2];

  queue_read(&ring, 0, &datas_read[0], iov, 0);
  queue_read(&ring, 1, &datas_read[1], iov, 1);

  struct io_uring_sqe *sqe;
  struct io_uring_cqe *cqe;

  while (1) {
    while (!io_uring_wait_cqe(&ring, &cqe)) {
      struct user_data *data = io_uring_cqe_get_data(cqe);
      if (data->read) {
        int read_from = data->index;
        int write_to = 1 - data->index;

        if (cqe->res > 0) {
          // enqueue write
          struct user_data *data_write = &datas_write[write_to];
          data_write->read = false;
          sqe = io_uring_get_sqe(&ring);
          io_uring_prep_write_fixed(sqe, write_to, iov[read_from].iov_base,
                                    cqe->res, 0, read_from);
          sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
          io_uring_sqe_set_data(sqe, data_write);
        }

        // enqueue read
        struct user_data *data_read = &datas_read[read_from];
        data_read->read = true;
        data_read->index = read_from;
        sqe = io_uring_get_sqe(&ring);
        io_uring_prep_read_fixed(sqe, read_from, iov[read_from].iov_base,
                                 iov[read_from].iov_len, 0, read_from);
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data(sqe, data_read);

        io_uring_submit(&ring);
      } else {
        // do nothing
      }
      io_uring_cqe_seen(&ring, cqe);
    }
  }

  io_uring_queue_exit(&ring);
}

int main() {

  int files[2];
  files[0] = tun_alloc("ping");
  files[1] = tun_alloc("pong");
  assert(files[0] >= 0);
  assert(files[1] >= 0);

  for (int i = 0; i < 5; i++) {
    pthread_t thread;
    pthread_create(&thread, NULL, run, files);
  }

  while (1) {
  }

  return 0;
}
