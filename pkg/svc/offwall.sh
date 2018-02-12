#!/sbin/sh

. /lib/svc/share/smf_include.sh

if [ -z $SMF_FMRI ]; then
  echo "SMF framework variables are not initialized."
  exit $SMF_EXIT_ERR
fi

PIDFILE=`svcprop -p offwall/pidfile $SMF_FMRI`
if [ -z $PIDFILE ]; then
  echo "offwall/pidfile property not set"
  exit $SMF_EXIT_ERR_CONFIG
fi

CSV=`svcprop -p offwall/csv $SMF_FMRI`
if [ -z $CSV ]; then
  echo "offwall/csv property not set"
  exit $SMF_EXIT_ERR_CONFIG
fi

LOG=`svcprop -p offwall/loglevel $SMF_FMRI`
if [ -z $LOG ]; then
  echo "offwall/loglevel property not set"
  exit $SMF_EXIT_ERR_CONFIG
fi

LOGV=
if [ $LOG -ne 0 ]; then
  i=1
  while [ $i -le $LOG ]; do
    LOGV=v$LOGV
    i=`expr $i + 1`
  done
  LOGV=-$LOGV
fi

case "$1" in
'start')
  LD_LIBRARY_PATH=/opt/csw/lib/64 /opt/offwall -p $PIDFILE -s $LOGV $CSV
  while [ ! -f "$PIDFILE" ]; do
    sleep 1
  done
  ;;
'stop')
  if [ -f "$PIDFILE" ]; then
    read PID <$PIDFILE
    ps -p $PID -o comm= | grep /opt/offwall
    if [ $? -ne 0 ]; then
      exit $SMF_EXIT_ERR
    fi
    kill $PID
    rm $PIDFILE
  fi
  ;;
*)
  echo "Usage: $0 <start|stop>"
  exit $SMF_EXIT_ERR
  ;;
esac

exit $SMF_EXIT_OK
