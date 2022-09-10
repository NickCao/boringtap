#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <linux/if.h>
#include <linux/if_tun.h>
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
  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
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

static void queue_write(struct io_uring *ring, int fd, struct user_data *data,
                        struct iovec *iov, size_t n) {
  struct io_uring_sqe *sqe;
  sqe = io_uring_get_sqe(ring);
  io_uring_prep_write_fixed(sqe, fd, iov[data->index].iov_base, n, 0,
                            data->index);
  data->read = false;
  io_uring_sqe_set_data(sqe, data);
  io_uring_submit(ring);
}

static void queue_read(struct io_uring *ring, int fd, struct user_data *data,
                       struct iovec *iov, size_t i) {
  struct io_uring_sqe *sqe;
  sqe = io_uring_get_sqe(ring);
  io_uring_prep_read_fixed(sqe, fd, iov[i].iov_base, iov[i].iov_len, 0, i);
  data->read = true;
  data->index = i;
  io_uring_sqe_set_data(sqe, data);
  io_uring_submit(ring);
}

int main() {
  struct io_uring ring;
  assert(!io_uring_queue_init(128, &ring, 0));

  struct iovec iov[2];
  for (int i = 0; i < 2; i++) {
    iov[i].iov_base = malloc(BUF_SIZE);
    iov[i].iov_len = BUF_SIZE;
  }
  io_uring_register_buffers(&ring, iov, 2);

  int ping = tun_alloc("ping");
  assert(ping >= 0);
  int pong = tun_alloc("pong");
  assert(pong >= 0);

  int fds[2];
  fds[0] = ping;
  fds[1] = pong;

  queue_read(&ring, fds[0], malloc(sizeof(struct user_data)), iov, 0);
  queue_read(&ring, fds[1], malloc(sizeof(struct user_data)), iov, 1);

  struct io_uring_cqe *cqe;
  while (1) {
    while (!io_uring_peek_cqe(&ring, &cqe)) {
      struct user_data *data = io_uring_cqe_get_data(cqe);
      size_t i = data->index;
      if (data->read) {
        if (cqe->res > 0) {
          queue_write(&ring, fds[1 - i], data, iov, cqe->res);
        }
        queue_read(&ring, fds[i], malloc(sizeof(struct user_data)), iov, i);
      } else {
        free(data);
      }
      io_uring_cqe_seen(&ring, cqe);
    }
  }

  io_uring_queue_exit(&ring);
  return 0;
}
