global stat: table[addr] of table[string] of count;
global num: table[addr] of count;
global now: time;
event zeek_init()
	{
	now = network_time();
	#print now;
	}
function init():string
{
	for(key in stat)
	{
		delete stat[key];
	}
	for(key in num)
	{
		delete num[key];
	}
	now = network_time();
}
event http_reply (c: connection, version: string, code: count, reason: string)
{
	#print code;
	#print c$http$uri;
	if(current_time()-now>10 min)
	{
		for(client in stat)
		{
			if(num[client]>2)
			{
				if(|stat[client]|/num[client]>0.5)
				{
					print fmt("%s is the orig_h,%d is the count of 404 response,%d is the unique count of url response 404",client,num[client],|stat[client]|);
				}
			}
			
		}
		init();
	}
	if(code==404)
	{
		if(c$id$orig_h !in stat)
		{
			local temp: table[string] of count = {[c$http$uri] = 1 };
			stat[c$id$orig_h]=temp;
		}
		else
		{
			if(c$http$uri !in stat[c$id$orig_h])
			{
				stat[c$id$orig_h][c$http$uri]=1;
			}
			else
			{
				stat[c$id$orig_h][c$http$uri]+=1;
			}
		}
		if(c$id$orig_h !in num)
		{
			num[c$id$orig_h]=1;
		}
		else
		{
			num[c$id$orig_h]+=1;
		}
		
	}
	
}
