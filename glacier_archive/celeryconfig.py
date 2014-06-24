#BROKER_URL = 'redis://localhost:6379/0'
#CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'America/New_York'
CELERY_ENABLE_UTC = True
CELERY_TASK_RESULT_EXPIRES = 100000
BROKER_URL = 'amqp://guest:guest@localhost:5672//'
CELERY_RESULT_BACKEND='amqp'
CELERYD_MAX_TASKS_PER_CHILD=10