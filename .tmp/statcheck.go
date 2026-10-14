package main
import ("fmt";"os")
func main(){ fi,_:=os.Lstat(".tmp/ptytmp/seqpass"); fmt.Printf("%v mode=%v sticky=%v\n", fi.Name(), fi.Mode().Perm(), fi.Mode()&os.ModeSticky)}
