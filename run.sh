source env.sh
cd fuzz

# use TLI2C_longSeed.hwf
python3 fuzz.py --time 3 --folder ./example --iterations 1  --- --FIRRTL test/resources/fuzzing/TLI2C.fir --Harness tlul --Directed --line-coverage --Feedback 255 --SeedInputFolder seeds --ThreadNum 1

# use TLUART_Seed.hwf
# python3 fuzz.py --time 3 --folder ./example --iterations 1  --- --FIRRTL test/resources/fuzzing/TLUART.fir --Harness tlul --Directed --line-coverage --Feedback 255 --SeedInputFolder seeds --ThreadNum 1

# use TLPWM_Seed.hwf
# python3 fuzz.py --time 3 --folder ./example --iterations 1  --- --FIRRTL test/resources/fuzzing/TLPWM.fir --Harness tlul --Directed --line-coverage --Feedback 255 --SeedInputFolder seeds --ThreadNum 1

# use rfuzz-zero-len500.hwf
# python3 fuzz.py --time 3 --folder ./example --iterations 1  --- --FIRRTL test/resources/fuzzing/Sodor1Stage.fir --Harness rfuzz --Directed --line-coverage --Feedback 255 --SeedInputFolder seeds --ThreadNum 1

# use rfuzz-zero-len5000.hwf
# python3 fuzz.py --time 3 --folder ./example --iterations 1  --- --FIRRTL test/resources/fuzzing/RocketTile.fir --Harness rfuzz --Directed --line-coverage --Feedback 255 --SeedInputFolder seeds --ThreadNum 1