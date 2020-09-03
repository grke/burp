#ifndef _PROMETHEUS_EXPORTER
#define _PROMETHEUS_EXPORTER

extern int prometheus_exporter_initialise(struct conf **confs);
extern void prometheus_exporter_free(void);
extern void prometheus_exporter_notify(struct asfd *asfd);
extern void prometheus_exporter_notify_removed(struct asfd *asfd);
extern void run_prometheus_exporter(struct asfd *asfd);

#endif
