Java.perform(() => {
  const AnswerHandler = Java.use('f.c');
  const field = AnswerHandler.class.getDeclaredField('a');
  field.setAccessible(true);
  const fieldValue = field.get(null);
  const appContext = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  const pendingIntent = Java.cast(fieldValue, AnswerHandler).a(appContext, 'wednesday');
  pendingIntent.send();
});
