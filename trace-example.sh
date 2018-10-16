#!/bin/bash
trap exit SIGINT;

# Which SPEC workload to run (test, train, etc.)
declare -A dataSets=(
			["bzip2"]="test"
			["mcf"]="test"
			["gobmk"]="test"
			["hmmer"]="test"
			["sjeng"]="test"
			["h264ref"]="test"
			["omnetpp"]="test"
			["astar"]="test"
			["xalancbmk"]="test"
		     )

declare -A longNames=(
			["bzip2"]="401.bzip2"
			["mcf"]="429.mcf"
			["gobmk"]="445.gobmk"
			["hmmer"]="456.hmmer"
			["sjeng"]="458.sjeng"
			["h264ref"]="464.h264ref"
			["omnetpp"]="471.omnetpp"
			["astar"]="473.astar"
			["xalancbmk"]="483.xalancbmk"
		     )

# The command to run for each SPEC program
declare -A commands=(
			["bzip2"]="input.program 5"
			["mcf"]="inp.in"
			["gobmk"]="--quiet --mode gtp < capture.tst"
			["hmmer"]="--fixed 0 --mean 325 --num 45000 --sd 200 --seed 0 bombesin.hmm"
			["sjeng"]="test.txt"
			["h264ref"]="-d foreman_test_encoder_baseline.cfg"
			["omnetpp"]="omnetpp.ini"
			["astar"]="lake.cfg"
			["xalancbmk"]="-v test.xml xalanc.xsl"
		    )

bench=$1
dataSet=${dataSets[$bench]}
longName=${longNames[$bench]}
_command=${commands[$bench]}
spec_path="/home/user/spec2006-install/"
run_path="$spec_path/benchspec/CPU2006/$longName/run/run_base_"$dataSet"_gcc43-64bit.0000/"
bin_path="/path/to/recompiled/binaries/${bench}"
bin_kb3main="/path/to/DynPointTo/build/KB3Main"

exec_analysis() {
  echo ""
  echo -e "\e[33mdo Running Analysis\e[0m"
  echo ""

  rm -f /tmp/mtime.special
  for x in {1..12}
  do
    echo -n "$x.."
    cd $bin_path

    # Disable ASLR
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
    # Get start and end addresses for IP filtering
    ffrom=`cat filter-range | grep -io "0x[0-9A-F]*" | head -n 1`
    fto=`cat filter-range | grep -io "0x[0-9A-F]*" | tail -n 1`
    # Configure uCFI kernel to trace target SPEC program
    echo -n $ffrom\|$fto\|$1.ptcfi | sudo tee /sys/kernel/debug/pt_monitor &> /dev/null
    # Start uCFI monitor
    sudo "$bin_kb3main" $1.wllvm.lowerSwitch.bc_pt.bc BB.info /sys/kernel/debug/pt_output BB.info &> /dev/null &

    # Run the SPEC program
    sleep 3
    cd $run_path
    eval '/usr/bin/time -f "real %e user %U sys %S" -a -o /tmp/mtime.special' $bin_path/$bench.ptcfi $_command &> /dev/null
    ps aux | grep "KB3Main" | grep -v "grep" &> /dev/null || result=1
    while (( result == 0 ))
    do
      sleep 2
      ps aux | grep "KB3Main" | grep -v "grep" &> /dev/null || result=1
    done

    # Disable uCFI kernel tracing
    echo -e "\x00" | sudo tee /sys/kernel/debug/pt_monitor

  done
  echo ""
  awk -v mi=1000 -v ma=0 '{ if ($2>ma) {ma=$2}; if ($2<mi) {mi=$2}; et += $2; ut += $4; st += $6; count++ } END { printf "Average:\nreal %.3f user %.3f sys %.3f\n", (et-mi-ma)/(count-2), ut/count, st/count;}' /tmp/mtime.special
}

case "$2" in
	analysis)
		exec_analysis
		;;
	*)
		echo "unknown option"
		exit 1
esac
