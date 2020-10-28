# sp2020-assignment

## 소스코드에 대한 설명
WIP

## 빌드하기

1. Makefile 내의 KDIR 수정
2. `make` 실행

## 커널 빌드하기

1. 커널 소스에 패치 파일 적용 ([여기](https://twpower.github.io/195-how-to-apply-patch-file) 참고)
2. 커널 빌드
```
make bzImage -j4 && make modules -j4
sudo make modules_install -j4 && sudo make install
```
3. 재부팅 후 빌드된 커널로 부팅

## 모듈 올리기

1. insmod 실행
2. proc 파일 읽어보기 (root로 실행)
```
cat /proc/inspectfs
```
