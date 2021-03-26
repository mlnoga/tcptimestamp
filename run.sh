#/bin/bas
find traces/ | grep -v '\.analysis' | xargs -n1 -P `nproc` -t -r ./tcptimestamps -g -r  
mkdir -p analyses/
mv traces/*.analysis analyses
