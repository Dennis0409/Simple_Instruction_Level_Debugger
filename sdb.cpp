#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <capstone/capstone.h>
#include "ptools.h"
#include <iostream>
#include <map>
#include <sstream>
#include <fstream>
#include <vector>
#include <elf.h>
#include <cstring>

using namespace std;

#define	PEEKSIZE	8

class instruction1 {
public:
	unsigned char bytes[16];
	int size;
	string opr, opnd;
};

static map<long long, instruction1> instructions;
static long long base=0;
static long long end_text=0;
static int out_of_memory=0;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

void print_instruction(long long addr, instruction1 *in) {
	//fprintf(stderr,"%llx\n",addr);
	if(addr>end_text-1&&out_of_memory==0){
		printf("** the address is out of the range of the text section.\n");
		out_of_memory=1;
		return ;
	}else if(out_of_memory==1) return ;
	//printf("addr:%llu\n",addr);
	int i;
	char bytes[128] = "";
	if(in == NULL) {
		fprintf(stderr, "0x%012llx:\t<cannot disassemble>\n", addr);
	} else {
		for(i = 0; i < in->size; i++) {
			snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
		}
		
		fprintf(stderr, "0x%012llx: %-32s\t%-10s%s\n", addr, bytes, in->opr.c_str(), in->opnd.c_str());
	}
}

void disassemble(pid_t proc, unsigned long long rip,unsigned long long end) {
	int count;
	char buf[100000] = { 0 };
	unsigned long long ptr = rip;
	cs_insn *insn;
	csh cshandle = 0;
	if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
		return ;
	for(ptr = rip; ptr < end; ptr += PEEKSIZE) {
		long long peek;
		errno = 0;
		peek = ptrace(PTRACE_PEEKTEXT, proc, ptr, NULL);
		if(errno != 0) break;
		memcpy(&buf[ptr-rip], &peek, PEEKSIZE);
		
	}

	if(ptr == rip)  {
		print_instruction(rip, NULL);
		return;
	}
	
	if((count = cs_disasm(cshandle, (uint8_t*) buf, ptr-rip, rip, 0, &insn)) > 0) {
		int i;
		for(i = 0; i < count; i++) {
			instruction1 in;
			in.size = insn[i].size;
			in.opr  = insn[i].mnemonic;
			in.opnd = insn[i].op_str;
			// fprintf(stderr,"rip:%012llx  insn[i]:%012llx  size:\n",rip,insn[i].address,in.size);
			memcpy(in.bytes, insn[i].bytes, insn[i].size);
			instructions[insn[i].address] = in;
			
		}
		cs_free(insn, count);
	}
	
	return;
}

void print_5_instruction(unsigned long rip){
	auto it = instructions.find(rip);
	for(int i=0;i<5;i++){
		print_instruction(it->first,&(it->second));
		it++;
	}
}

int get_base_addr(char* argv){
	std::ifstream file(argv, std::ios::binary);

    if (!file) {
        std::cerr << "無法開啟檔案" << std::endl;
        return 1;
    }

    // 讀取 ELF 標頭
    Elf64_Ehdr ehdr;
    file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));

    // 定位節頭表的位置
    file.seekg(ehdr.e_shoff, std::ios::beg);

    // 讀取節頭表
    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    file.read(reinterpret_cast<char*>(shdrs.data()), sizeof(Elf64_Shdr) * shdrs.size());

    // 找到節頭名稱字串表的節頭
    Elf64_Shdr shstrtab_shdr = shdrs[ehdr.e_shstrndx];

    // 讀取節頭名稱字串表
    std::vector<char> shstrtab(shstrtab_shdr.sh_size);
    file.seekg(shstrtab_shdr.sh_offset, std::ios::beg);
    file.read(shstrtab.data(), shstrtab_shdr.sh_size);
	file.close();
    // 找到名稱為 .text 的節頭
    Elf64_Shdr text_shdr;
    for (const Elf64_Shdr& shdr : shdrs) {
        std::string section_name = &shstrtab[shdr.sh_name];
        if (section_name == ".text") {
            text_shdr = shdr;
            break;
        }
    }

	base=text_shdr.sh_addr;
	end_text=base+text_shdr.sh_size;
	// fprintf(stderr,"base : %12llx end_text : %12llx \n",base,end_text);
	return 0;
}

int main(int argc, char *argv[]) {
	if(get_base_addr(argv[1])) return 1;
	if(argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}
	pid_t child;
	if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execvp(argv[1], argv+1);
		errquit("execvp");
	} else {
		int wait_status;
		map<range_t, map_entry_t> m;
		map<range_t, map_entry_t>::iterator mi;

		if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

		if(load_maps(child, m) > 0) {
#if 0
			for(mi = m.begin(); mi != m.end(); mi++) {
				fprintf(stderr, "## %lx-%lx %04o %s\n",
					mi->second.range.begin, mi->second.range.end,
					mi->second.perm, mi->second.name.c_str());
			}
#endif
			fprintf(stderr, "## %zu map entries loaded.\n", m.size());
		}
		
		disassemble(child,base,end_text);
		map<unsigned long,long >addr_break;
		string cmd;
		struct user_regs_struct travel_regs;
		map<pair<unsigned long,unsigned long>,vector<unsigned long long>>travel_mem;
		struct user_regs_struct regs_start;

		if(ptrace(PTRACE_GETREGS,child,0,&regs_start)!=0) errquit("Getregs error");
		print_5_instruction(regs_start.rip);
		while (cerr<<"(sdb) ") {
			if(!getline(cin,cmd)) break;
			size_t found;
			//unsigned long code;
			if(cmd=="si"){
				struct user_regs_struct regs;
				ptrace(PTRACE_GETREGS,child,0,&regs);
				//fprintf(stderr, "before si:0x%llx\n", regs.rip);
				if(addr_break.find(regs.rip)!=addr_break.end()){
					
					unsigned long code_target=ptrace(PTRACE_PEEKTEXT,child,regs.rip,0);
					unsigned long code_ori=addr_break[regs.rip] & 0xff;
					if(ptrace(PTRACE_POKETEXT,child,regs.rip,(code_target & 0xffffffffffffff00) | code_ori)!=0) errquit("poketext");
					
					//ptrace(PTRACE_SETREGS,child,0,&regs);
					if(ptrace(PTRACE_SINGLESTEP,child,0,0)<0) errquit("singlestep");
					if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
					if(ptrace(PTRACE_POKETEXT,child,regs.rip,code_target)!=0) errquit("ptrace poketext");
					
				}else{
					if(ptrace(PTRACE_SINGLESTEP,child,0,0)<0) errquit("singlestep");
					if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
				}
				
				if(WIFEXITED(wait_status)){
					cerr<<"** the target program terminated.\n";
					return 0;
				}
				if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("Getregs error");
				
				if(addr_break.find(regs.rip)!=addr_break.end()){
					fprintf(stderr,"** hit a breakpoint 0x%012llx.\n",regs.rip);
				}
				print_5_instruction(regs.rip);
				out_of_memory=0;

			}
			else if((found=cmd.find("break"))!=string::npos){
				unsigned long addr_break_temp=stoul(cmd.substr(found+6),nullptr,16);
				unsigned long code=ptrace(PTRACE_PEEKTEXT,child,addr_break_temp,0);
				addr_break[addr_break_temp]=code;
				fprintf(stderr,"** set a breakpoint at 0x%012llx\n",addr_break_temp);
				if(ptrace(PTRACE_POKETEXT,child,addr_break_temp,(code & 0xffffffffffffff00)|0xcc)!=0){
					errquit("ptrace(POKETEXT)");
				}
				
			}else if(cmd=="cont"){
				struct user_regs_struct regs;
				ptrace(PTRACE_GETREGS,child,0,&regs);
				if(addr_break.find(regs.rip)!=addr_break.end()){
					unsigned long code_target=ptrace(PTRACE_PEEKTEXT,child,regs.rip,0);
					unsigned long code_ori=addr_break[regs.rip] & 0xff;
					if(ptrace(PTRACE_POKETEXT,child,regs.rip,(code_target & 0xffffffffffffff00) | code_ori)!=0) errquit("poketext");
					
					//ptrace(PTRACE_SETREGS,child,0,&regs);
					if(ptrace(PTRACE_SINGLESTEP,child,0,0)<0) errquit("singlestep");
					if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
					if(ptrace(PTRACE_POKETEXT,child,regs.rip,code_target)!=0) errquit("ptrace poketext");
				}

				if(ptrace(PTRACE_CONT,child,0,0)!=0) errquit("ptrace(cont)");

				while(waitpid(child,&wait_status,0)>0){
					if(WIFEXITED(wait_status)){
						cerr<<"** the target program terminated.\n";
						return 0;
					}
					if(!WIFSTOPPED(wait_status)){
						continue;
					}
					
					if(ptrace(PTRACE_GETREGS,child,0,&regs)!=0) errquit("getregs");
					if(addr_break.find(regs.rip-1)!=addr_break.end()){
						fprintf(stderr,"** hit a breakpoint 0x%012llx.\n",regs.rip-1);
						print_5_instruction(regs.rip-1);
						regs.rip--;
						if(ptrace(PTRACE_SETREGS,child,0,&regs)!=0) errquit("setregs");
					}
					break;
				}
					
			}else if(cmd=="anchor"){
				fprintf(stderr,"** dropped an anchor\n");
				//store current register
				if(ptrace(PTRACE_GETREGS,child,0,&travel_regs)!=0) errquit("ptrace(getregs)");

				//store current memory
				string buf;
				char t[10240];
				sprintf(t,"/proc/%d/maps",child);

				ifstream maps_file(t);
				while(getline(maps_file,buf)){
					const char*str_c=buf.c_str();
					if(strstr(str_c,"[stack]")!=NULL){
						break;		
					}
					unsigned long start,end;
					stringstream ss(buf);
					string token;
					getline(ss,token,'-');
					start=stol(token,nullptr,16);
					getline(ss,token,' ');
					end=stol(token,nullptr,16);

					for (auto addr=start;addr<end; addr += sizeof(unsigned long long)) {
						unsigned long long data = ptrace(PTRACE_PEEKDATA, child, addr, nullptr);
						travel_mem[{start,end}].push_back(data);
					}
				}
				maps_file.close();

			}else if(cmd=="timetravel"){
				fprintf(stderr,"** go back to the anchor point\n");
				//restore register
				if(ptrace(PTRACE_SETREGS,child,0,&travel_regs)==-1) errquit("setregs");

				//restore memory
				for(auto [p,data]:travel_mem){
					unsigned long start=p.first;
					unsigned long end=p.second;
					long j=0;
					for(auto i = start; i <end; i += sizeof(unsigned long long)){
						if(ptrace(PTRACE_POKEDATA,child,i,data[j++])==-1) errquit("pokedata");
					}
				}

				//restore break points
				for(auto [addr,code_ori]:addr_break){
					unsigned long long code=ptrace(PTRACE_PEEKTEXT,child,addr,0);
					if(ptrace(PTRACE_POKETEXT,child,addr,(code & 0xffffffffffffff00) | 0xcc)!=0) errquit("poketext");
					if(addr==travel_regs.rip){
						fprintf(stderr,"** hit a breakpoint 0x%012llx.\n",addr);
					}
				}
				print_5_instruction(travel_regs.rip);
				out_of_memory=0;
			}else fprintf(stderr,"Please input si, break (address), cont, anchor or timetravel\n");
		}
	}
	return 0;
}

