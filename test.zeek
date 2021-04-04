global nameofip:table[addr] of set[string]=table();
global sum:table[addr] of int= table();
event http_header(c:connection,is_orig:bool,name:string,value:string)
{
    local ipaddr:addr;
    if (name=="USER-AGENT")
    {
        ipaddr=c$id$orig_h;
        if (ipaddr in nameofip)
        {
            if (to_lower(value) !in nameofip[ipaddr])
            {
               add nameofip[ipaddr][to_lower(value)];
               sum[ipaddr]=sum[ipaddr]+1;
            } 
        }
        else 
        {
           nameofip[ipaddr]=set(to_lower(value));
           sum[ipaddr]=1;
        }
    }
}
event zeek_done()
{
    local ipaddr:addr;
    for (ipaddr in nameofip)
    {
        if (sum[ipaddr]>=3)
        {
            print fmt("%s is a proxy",ipaddr);
        }
    }
}

