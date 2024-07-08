all:
	gcc -D_GNU_SOURCE -std=c11 -Wall -Wextra l4proxy.c -o l4proxy
clean:
	rm l4proxy
