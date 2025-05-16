.PHONY: all clean

# all: vdec_params.h
all: params

# _fhe_example_params_cffi.o: fhe_example_params.h ../_lazer_cffi.o
#	python3 ../params_cffi_build.py fhe_example_params.h ../..

params:
	cd ../scripts && sage vdec_params_generator.sage ../vdec/vdec_params.sage > ../vdec/vdec_params.h
# 	cd ../scripts && sage lnp-quad-eval-codegen.sage ../vdec/lnp-quad-eval-params1.sage > ../vdec/lnp-quad-eval-params1.h
# 	cd ../scripts && sage lnp-tbox-codegen.sage ../vdec/vdec_params_tbox.sage > ../vdec/vdec_params_tbox.h
#	cd ../scripts && sage lin-codegen.sage ../vdec/vdec_params.sage > ../vdec/vdec_params.h

#../_lazer_cffi.o:
#	cd .. && make

clean:
	rm -rf __pycache__
	rm -f *.o *.so
