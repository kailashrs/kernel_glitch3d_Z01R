make clean
export PATH="/home/kailashrs/5z/proton_clang/bin:${PATH}"
export LD_LIBRARY_PATH="$/home/kailashrs/5z/proton_clang/bin../lib:$LD_LIBRARY_PATH"
export ARCH="arm64"
export CROSS_COMPILE="aarch64-linux-gnu-"
export CROSS_COMPILE_ARM32="arm-linux-gnueabi-"
make O=out Z01R_defconfig
make CC=clang LD=ld.lld O=out -j$(nproc --all)
cd ..
cd AnyKernel3
rm zImage
rm dtbo.img
rm glitch3d.zip
python2 /home/kailashrs/5z/mkdtboimg.py create dtbo.img /home/kailashrs/5z/glitch3d/out/arch/arm64/boot/dts/qcom/*.dtbo
cp /home/kailashrs/5z/glitch3d/out/arch/arm64/boot/Image.gz-dtb zImage
zip -r glitch3d.zip *
