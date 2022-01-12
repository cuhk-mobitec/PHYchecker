echo "this is for analyzing apk..."
starttime=`date +'%Y-%m-%d %H:%M:%S'`
echo "start time:"$starttime

apk_dir="./camera-apks"
log_dir="./output/run.log"

find $apk_dir -name '*.apk'| parallel --resume --joblog $log_dir --jobs 24 "python camera1_checker.py {} > ./result/{}.log"

endtime=`date +'%Y-%m-%d %H:%M:%S'`
echo "end time:"$endtime
