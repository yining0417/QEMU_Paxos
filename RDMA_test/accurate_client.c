/*
 * Copyright (c) 2010 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

static char *server = "10.22.1.1";
static char *port = "7471";

struct rdma_cm_id *id;
struct ibv_mr *mr, *send_mr;
int send_flags;
uint8_t send_msg[160];
uint8_t recv_msg[160];

pthread_t ntid;

void *run(void *arg)
{
	struct rdma_addrinfo hints, *res;
	struct ibv_qp_init_attr attr;
	struct ibv_wc wc;
	int ret;

	memset(&hints, 0, sizeof hints);
	hints.ai_port_space = RDMA_PS_TCP;
	ret = rdma_getaddrinfo(server, port, &hints, &res);
	if (ret) {
		perror("rdma_getaddrinfo");
		goto out;
	}

	memset(&attr, 0, sizeof attr);
	attr.cap.max_send_wr = attr.cap.max_recv_wr = 1;
	attr.cap.max_send_sge = attr.cap.max_recv_sge = 1;
	attr.cap.max_inline_data = 16;
	attr.qp_context = id;
	attr.sq_sig_all = 1;
	ret = rdma_create_ep(&id, res, NULL, &attr);
	// Check to see if we got inline data allowed or not
	if (attr.cap.max_inline_data >= 16)
		send_flags = IBV_SEND_INLINE;
	else
		printf("rdma_client: device doesn't support IBV_SEND_INLINE, "
		       "using sge sends\n");

	if (ret) {
		perror("rdma_create_ep");
		goto out_free_addrinfo;
	}

	mr = rdma_reg_msgs(id, recv_msg, 16);
	if (!mr) {
		perror("rdma_reg_msgs for recv_msg");
		ret = -1;
		goto out_destroy_ep;
	}
	if ((send_flags & IBV_SEND_INLINE) == 0) {
		send_mr = rdma_reg_msgs(id, send_msg, 16);
		if (!send_mr) {
			perror("rdma_reg_msgs for send_msg");
			ret = -1;
			goto out_dereg_recv;
		}
	}
	memset(recv_msg,0,sizeof(recv_msg));
	ret = rdma_post_recv(id, NULL, recv_msg, 16, mr);
	if (ret) {
		perror("rdma_post_recv");
		goto out_dereg_send;
	}

	ret = rdma_connect(id, NULL);
	if (ret) {
		perror("rdma_connect");
		goto out_dereg_send;
	}
	sprintf((char*)send_msg,"This is a slave");
	ret = rdma_post_send(id, NULL, send_msg, 16, send_mr, send_flags);
	if (ret) {
		perror("rdma_post_send");
		goto out_disconnect;
	}

	while ((ret = rdma_get_send_comp(id, &wc)) == 0);
	if (ret < 0) {
		perror("rdma_get_send_comp");
		goto out_disconnect;
	}

	while ((ret = rdma_get_recv_comp(id, &wc)) == 0);
	if (ret < 0)
		perror("rdma_get_recv_comp");
	else
		ret = 0;

	printf("recv:%s\n",recv_msg);
out_disconnect:
	rdma_disconnect(id);
out_dereg_send:
	if ((send_flags & IBV_SEND_INLINE) == 0)
		rdma_dereg_mr(send_mr);
out_dereg_recv:
	rdma_dereg_mr(mr);
out_destroy_ep:
	rdma_destroy_ep(id);
out_free_addrinfo:
	rdma_freeaddrinfo(res);
out:
	return ((void *)0);
}

int main(int argc, char **argv)
{
	int ret;

	printf("rdma_client: start\n");
	int temp;
        if((temp=pthread_create(&ntid,NULL,run,NULL))!= 0)
        {
            printf("can't create thread: %s\n",strerror(temp));
            return 1;
         }

	printf("rdma_client: end %d\n", ret);
        pthread_exit(NULL);
	return ret;
}
