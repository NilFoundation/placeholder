cmake_minimum_required(VERSION 3.22 FATAL_ERROR)
#set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
#set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")
project(parallel-crypto3)

option(BUILD_PARALLEL_CRYPTO3_TESTS "Enable tests" TRUE)
set(CMAKE_CUDA_COMPILER nvc++)

find_package(CM REQUIRED)
# list(APPEND CMAKE_PREFIX_PATH /root/sycl/lib/cmake/AdaptiveCpp/)
# find_package(AdaptiveCpp CONFIG REQUIRED)
include(CMConfig)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# add_compile_options(-v)
# #add_compile_options(--hipsycl-platform=cuda --hipsycl-gpu-arch=sm_75 --hipsycl-targets=cuda:sm_75 --hipsycl-cuda-path=/var/empty/local/cuda/ --hipsycl-nvcxx=/var/empty/nvidia/hpc_sdk/Linux_x86_64/24.9/compilers/bin/nvc++)
# #add_compile_options(-I/nix/store/wkpm1n7q62pbs8ck6ad5i7zklr1k9il0-OpenSYCL-0.9.4/include/)
# add_compile_options(-I/root/sycl/include/AdaptiveCpp/)
# add_compile_options(-I/nix/store/x8rg4vhgd20i8vzykm1196f9qdb8klhh-gcc-13.3.0/include/c++/13.3.0/)
# add_compile_options(-I/nix/store/x8rg4vhgd20i8vzykm1196f9qdb8klhh-gcc-13.3.0/include/c++/13.3.0/x86_64-unknown-linux-gnu/)

# add_compile_options(-I/nix/store/ifqg35znvnvay7j5zank40jc7p016zi8-cuda_cccl-12.4.99-dev/include/cuda/std/detail/libcxx/include/)

# add_link_options(-L/nix/store/22nxhmsfcv2q2rpkmfvzwg2w5z1l231z-gcc-13.3.0-lib/lib64/)
# #add_link_options(-L/nix/store/sl141d1g77wvhr050ah87lcyz2czdxa3-glibc-2.40-36/lib64/)
# #add_link_options(-L/nix/store/yldgl6y1dy6nmvy9gza0flgh9is3k4s1-libcxx-18.1.8/lib)

# add_link_options(-Xlinker -dynamic-linker -Xlinker /nix/store/sl141d1g77wvhr050ah87lcyz2czdxa3-glibc-2.40-36/lib64/ld-linux-x86-64.so.2)

# add_link_options(-L/root/sycl/lib/hipSYCL/)
# add_link_options(-L/root/sycl/lib/)

# add_link_options(-L/usr/local/cuda/lib64)
# add_link_options(-L/usr/local/cuda/lib64/stubs/)
# add_link_options(-L/opt/nvidia/hpc_sdk/Linux_x86_64/24.9/cuda/12.6/compat/)
# # add_link_options(-L/usr/lib/x86_64-linux-gnu/)

# add_link_options(-rpath=/root/sycl/lib/hipSYCL/)
# add_link_options(-rpath=/root/sycl/lib/)

# add_link_options(-rpath=/usr/local/cuda/lib64)
# add_link_options(-rpath=/usr/local/cuda/lib64/stubs/)
# add_link_options(-rpath=/opt/nvidia/hpc_sdk/Linux_x86_64/24.9/cuda/12.6/compat/)

# add_link_options(-rpath=/usr/lib/x86_64-linux-gnu/)
# add_link_options(-rpath=/nix/store/53iigsmf32bwkfdhhihq2rppgk23k2rg-ncurses-6.4.20221231/lib/)

# add_link_options(-lacpp-rt -lacpp-common -lcuda -lrt-backend-cuda)
# add_link_options(-ledit -ltinfo -lffi -lz -lxml2 -licuuc -licui18n -licudata -llzma)
# add_link_options(-lstdc++ -lc -v)
add_link_options(-L/usr/local/cuda/lib64)
add_link_options(-Wl,-rpath=/usr/local/cuda/lib64)
add_link_options(-L/usr/local/cuda/lib64/stubs/)
add_link_options(-Wl,-rpath=/usr/local/cuda/lib64/stubs/)
add_link_options(-L/root/acpp/lib/hipSYCL/)
add_link_options(-Wl,-rpath=/root/acpp/lib/hipSYCL/)
add_link_options(-L/opt/nvidia/hpc_sdk/Linux_x86_64/24.9/REDIST/cuda/12.6/compat/)
add_link_options(-Wl,-rpath=/opt/nvidia/hpc_sdk/Linux_x86_64/24.9/REDIST/cuda/12.6/compat/)
add_link_options(-L/nix/store/1m2jrj85fmj0sqjp8bk8hf1j6wnb1lpc-openmp-19.1.1/lib/)
add_link_options(-Wl,-rpath=/nix/store/1m2jrj85fmj0sqjp8bk8hf1j6wnb1lpc-openmp-19.1.1/lib/)
add_link_options(-L/opt/nvidia/hpc_sdk/Linux_x86_64/24.9/REDIST/cuda/12.6/lib64)
add_link_options(-Wl,-rpath=/opt/nvidia/hpc_sdk/Linux_x86_64/24.9/REDIST/cuda/12.6/lib64)
add_link_options(-lrt-backend-cuda -lcuda -lacpp-rt -lacpp-common -lomp -lnvJitLink -lnvidia-ptxjitcompiler)

#add_compile_options(-I/opt/intel/oneapi/2025.0/include/)
#add_compile_options(-I/opt/intel/oneapi/2025.0/include/sycl/)
#add_compile_options(-Wl,-rpath -Wl,/opt/intel/oneapi/2025.0/lib/)
#add_compile_options(-Wl,-rpath=/root/sycl_workspace/llvm/build/install/lib/)
#add_compile_options(-I/nix/store/x8rg4vhgd20i8vzykm1196f9qdb8klhh-gcc-13.3.0/include/c++/13.3.0/tr1/)
#add_compile_options(-I/nix/store/n15bxkd7id2gvlwpihm4kp675aqkrwmj-glibc-2.40-36-dev/include/)
#add_compile_options(-I/nix/store/x8rg4vhgd20i8vzykm1196f9qdb8klhh-gcc-13.3.0/include/c++/13.3.0/x86_64-unknown-linux-gnu/)
# add_link_options(-L/opt/intel/oneapi/2025.0/lib/)
# add_link_options(-L/nix/store/sl141d1g77wvhr050ah87lcyz2czdxa3-glibc-2.40-36/lib64/)
# add_link_options(-L/nix/store/22nxhmsfcv2q2rpkmfvzwg2w5z1l231z-gcc-13.3.0-lib/lib64/)
# #add_link_options(-rpath /opt/intel/oneapi/2025.0/lib/ -rpath /root/sycl_workspace/llvm/build/install/lib/)
# add_link_options(-Xlinker -dynamic-linker -Xlinker /nix/store/sl141d1g77wvhr050ah87lcyz2czdxa3-glibc-2.40-36/lib64/ld-linux-x86-64.so.2)
# #add_link_options(-lsycl -lur_loader -limf -lsvml -lirng -lintlc -lz -v) # -lstdc++ -lc -lz

# add_compile_options(-fsycl -fsycl-targets=nvptx64-nvidia-cuda)
# add_compile_options(-I/root/sycl_workspace/llvm/build/install/include/)
# add_compile_options(--cuda-path=/usr/local/cuda/)
# add_link_options(-L/root/sycl_workspace/llvm/build/install/lib/)
# add_link_options(-rpath /root/sycl_workspace/llvm/build/install/lib/:/opt/intel/oneapi/2025.0/lib/:/nix/store/2k9k3q1vk8z6w7743k6nb22vnb05xv06-zlib-1.3.1/lib/)
# add_link_options(-lsycl -lur_loader -limf -lsvml -lirng -lintlc -lz -v)


# The file compile_commands.json is generated in build directory, so LSP could
# pick it up and guess all include paths, defines and other stuff.
# If Nix is used, LSP could not guess the locations of implicit include
# directories, so we need to include them explicitly.
if(CMAKE_EXPORT_COMPILE_COMMANDS)
  set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES
      ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})
endif()

# TODO: check what is actually required here
include(CMSetupVersion)

# TODO: beutify entire cmake tree of parallel crypto3 modules the same way we did in origin crypto3
find_package(Boost REQUIRED COMPONENTS filesystem log program_options thread random unit_test_framework container)

function(add_tests)
    if (${BUILD_PARALLEL_CRYPTO3_TESTS})
        add_subdirectory(test)
    endif ()
endfunction(add_tests)

add_subdirectory(libs/parallelization-utils)
add_subdirectory(libs/parallel-containers)
add_subdirectory(libs/parallel-math)
add_subdirectory(libs/parallel-zk)

add_library(${PROJECT_NAME}_all INTERFACE)
add_library(${PROJECT_NAME}::all ALIAS ${PROJECT_NAME}_all)
target_link_libraries(${PROJECT_NAME}_all INTERFACE
    actor::containers
    actor::math
    actor::zk
    actor::core
    )

# Configure package file to be able to import headers
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
set(CONFIG_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/parallel-crypto3)

configure_package_config_file(
        cmake/Config.cmake.in
        parallel-crypto3Config.cmake
        INSTALL_DESTINATION ${CONFIG_DIR}
)

install(
        FILES
        ${CMAKE_CURRENT_BINARY_DIR}/parallel-crypto3Config.cmake
        DESTINATION ${CONFIG_DIR}
)
