/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package oom_cp_abe;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.StringTokenizer;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author ALOK
 */


/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


/**
 *
 * @author ALOK
 */
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import java.security.NoSuchAlgorithmException;
import java.io.ByteArrayInputStream;
import static java.lang.System.currentTimeMillis;

import java.util.ArrayList;
import java.util.Scanner;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.StringTokenizer;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.Queue;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class Bswabe_Pub{
	/*
	 * A public key
	 */
	public String pairingDesc;
	public Pairing p;				
	public Element g;				/* G_1 */
	public Element h;				/* G_1 */
	public Element f;				/* G_1 */
	public Element gp;			/* G_2 */
	public Element g_hat_alpha;	/* G_T */
}

class Bswabe_Msk {
	/*
	 * A master secret key
	 */
	public Element beta; /* Z_r */
	public Element g_alpha; /* G_2 */	
}

class Bswabe_Prv {
	/*
	 * A private key
	 */
	Element d; /* G_2 */
        Element r;
	ArrayList<Bswabe_PrvComp> comps; /* BswabePrvComp */
}

class Bswabe_PrvComp {
	/* these actually get serialized */
	String attr;
	Element d;					/* G_2 */
	Element dp;				/* G_2 */
	
	/* only used during dec */
	int used;
	Element z;					/* G_1 */
	Element zp;				/* G_1 */
}


class Bswabe_CphKey {
	/*
	 * This class is defined for some classes who return both cph and key.
	 */
	public Bswabe_Cph cph;
	public Element key;
}


 class Bswabe_Cph {
	/*
	 * A ciphertext. Note that this library only handles encrypting a single
	 * group element, so if you want to encrypt something bigger, you will have
	 * to use that group element as a symmetric key for hybrid encryption (which
	 * you do yourself).
	 */
	public Element cs; /* G_T */
	public Element c; /* G_1 */
	public Bswabe_Policy p;
}


class Bswabe_Element_Boolean {
	/*
	 * This class is defined for some classes who return both boolean and
	 * Element.
	 */
	public Element e;
	public boolean b;
}


class Bswabe_Polynomial {
	int deg;
	/* coefficients from [0] x^0 to [deg] x^deg */
	Element[] coef; /* G_T (of length deg+1) */
}
 class Bswabe_Policy {
	/* serialized */
	/* k=1 if leaf, otherwise threshould */
	int k;
	/* attribute string if leaf, otherwise null */
	String attr;
	Element c;			/* G_1 only for leaves */
	Element cp;		/* G_1 only for leaves */
	/* array of BswabePolicy and length is 0 for leaves */
	Bswabe_Policy[] children;
	/* only used during encryption */
	Bswabe_Polynomial q;
	/* only used during decription */
	boolean satisfiable;
	int min_leaves;
	int attri;
	ArrayList<Integer> satl = new ArrayList<Integer>();
}

class Make_Setup {
     

	 String curveParams = "type a\n"
			+ "q 87807107996633125224377819847540498158068831994142082"
			+ "1102865339926647563088022295707862517942266222142315585"
			+ "8769582317459277713367317481324925129998224791\n"
			+ "h 12016012264891146079388821366740534204802954401251311"
			+ "822919615131047207289359704531102844802183906537786776\n"
			+ "r 730750818665451621361119245571504901405976559617\n"
			+ "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n";

	    void setup(Bswabe_Pub pub, Bswabe_Msk msk) {
		Element alpha, beta_inv;

	PropertiesParameters params = new PropertiesParameters()
				.load(new ByteArrayInputStream(curveParams.getBytes()));

		pub.pairingDesc = curveParams;
		pub.p= PairingFactory.getPairing(params);
		Pairing pairing = pub.p;
                //System.out.println(pub.p);
		pub.g = pairing.getG1().newElement();
		pub.f = pairing.getG1().newElement();
		pub.h = pairing.getG1().newElement();
		pub.gp = pairing.getG2().newElement();
		pub.g_hat_alpha = pairing.getGT().newElement();
		alpha = pairing.getZr().newElement();
		msk.beta = pairing.getZr().newElement();
	        msk.g_alpha = pairing.getG2().newElement();

		alpha.setToRandom();
                msk.beta.setToRandom();
                
                pub.g.setToRandom();
               
                System.out.println("**************Setup Function:*****************");
              System.out.println("Element of group G1:");
               System.out.println("The value of g  is :");
                System.out.println(pub.g);
	        pub.gp.setToRandom();

		msk.g_alpha = pub.gp.duplicate();
		msk.g_alpha.powZn(alpha);
                System.out.println("g to the power alpha");
                System.out.println(msk.g_alpha);

		beta_inv = msk.beta.duplicate();
		beta_inv.invert();
		
                pub.f = pub.g.duplicate();
	        pub.f.powZn(beta_inv);
                
                System.out.println("g to the power beta inverse");
                System.out.println(pub.f);

		pub.h = pub.g.duplicate();
		pub.h.powZn(msk.beta);
                System.out.println("g to the power beta");
                System.out.println(pub.h);

		pub.g_hat_alpha = pairing.pairing(pub.g,msk.g_alpha);
                System.out.println("billenear map of g and g alpha");
                System.out.println("Element of group GT:");
                System.out.println(pub.g_hat_alpha);
                
	}
            
 }

class Key_Generation
        
{
    //Element d;
   
    Bswabe_Prv secretkey(Bswabe_Pub pub, Bswabe_Msk msk, String [] attrs)
    {
        Bswabe_Prv prv = new Bswabe_Prv();
        Pairing pair;
        pair=pub.p;
        prv.d=pair.getG2().newElement();
        prv.d=msk.g_alpha.duplicate();
        
        
        Element r;
        r=pair.getZr().newElement();
        r.setToRandom();
        
        Element gr;
         gr=pair.getG2().newElement();
         gr=pub.gp.duplicate();
         gr.powZn(r);
         
         prv.d.mul(gr);
         
         Element bi;
         bi=pair.getZr().newElement();
         bi=msk.beta.duplicate();
         bi.invert();
         prv.d.powZn(bi);
         
         System.out.println("**************************Key Generation Function***********************");
         
         System.out.println("The value of d  that is g to the power (alpha + r)/ beta is");
         System.out.println(prv.d);
         
         /*Scanner sc=new Scanner(System.in);
         System.out.println("enter the number of attributes of user");
       
         int n=sc.nextInt();
         sc.nextLine();
         String[] attributes=new String[n];
         int i;
         System.out.println("enter the attributes");
         for(i=0;i<n;i++)
         {
             attributes[i]=sc.nextLine();
             
        }
          System.out.println("the attributes are :");
         for(i=0;i<n;i++)
         {
             System.out.println(attributes[i]);
         
    
}*/
         int i, len = attrs.length;
         System.out.println("FOR EVERY ATTRIBUTE ");
         
         prv.comps = new ArrayList<Bswabe_PrvComp>();
         
         for(i=0;i<len;i++)
         {
             Bswabe_PrvComp comp = new Bswabe_PrvComp();
             //User u=new User();
             Element h_rp;
             
             comp.attr=attrs[i];
             
             Element rp;
             rp=pair.getZr().newElement();
             rp.setToRandom();
             
             comp.d = pair.getG2().newElement();
             comp.dp = pair.getG1().newElement();
             h_rp = pair.getG2().newElement();
             
             
             comp.d=gr.duplicate();
             
                         
             try
             {
             elementFromString(h_rp,attrs[i]);
             
             System.out.println(" hash generated");
             }
             catch(Exception e)
                     {
                         System.out.println("catch of hash hash");
                     }
             
             h_rp.powZn(rp);
             
             comp.d.mul(h_rp);
             
             comp.dp=pub.g.duplicate();
             comp.dp.powZn(rp);
                     
             prv.comps.add(comp);
                    
                   
             
      }
         return prv;
}
    	private static void elementFromString(Element h, String s)
			throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] digest = md.digest(s.getBytes());
		h.setFromHash(digest, 0, digest.length);
	}
}


class Ciphertext
{
  static Bswabe_CphKey keyCph;
  static     Bswabe_Cph cph;
  static      Element s,m;
  static      Pairing pa;
  static      String policy;
  static      Bswabe_Pub pub;
       
    
}
class enc_init_set extends Ciphertext
            {
    
enc_init_set()
{}
        enc_init_set(Bswabe_Pub pub, String policy)
    {
        
        cph = new Bswabe_Cph();
        
        super.policy=policy;
        super.pub=pub;
        pa=pub.p;
        s=pa.getZr().newElement();
         s.setToRandom();
     //      System.out.println("pa in init"+pa);
   //System.out.println("s in init"+s);         
  
    }
         Bswabe_CphKey set_cph_key()
    {
        keyCph = new Bswabe_CphKey();
		keyCph.key = m;
                keyCph.cph = cph;
		return keyCph;
}
}
     
class enc_parse_policy extends Ciphertext implements Runnable
            {
   
      public void run()
    {
  //      System.out.println("......."+policy);
        try
        {
	cph.p = parse_Policy_Postfix(policy);
        }
        catch(Exception e)
        {
            System.out.println("exception in parse policy");
        }
    }
      private static Bswabe_Policy parse_Policy_Postfix(String s) throws Exception {
		String[] toks;
		String tok;
		ArrayList<Bswabe_Policy> stack = new ArrayList<Bswabe_Policy>();
		Bswabe_Policy root;

		toks = s.split(" ");

		int toks_cnt = toks.length;
    //            System.out.println("inside parse");
		for (int index = 0; index < toks_cnt; index++) {
			int i, k, n;

			tok = toks[index];
			if (!tok.contains("of")) {
				stack.add(base_Node(1, tok));
			} else {
				Bswabe_Policy node;

				/* parse kof n node */
				String[] k_n = tok.split("of");
				k = Integer.parseInt(k_n[0]);
				n = Integer.parseInt(k_n[1]);

				if (k < 1) {
					System.out.println("error parsing " + s
							+ ": trivially satisfied operator " + tok);
					return null;
				} else if (k > n) {
					System.out.println("error parsing " + s
							+ ": unsatisfiable operator " + tok);
					return null;
				} else if (n == 1) {
					System.out.println("error parsing " + s
							+ ": indentity operator " + tok);
					return null;
				} else if (n > stack.size()) {
					System.out.println("error parsing " + s
							+ ": stack underflow at " + tok);
					return null;
				}

				/* pop n things and fill in children */
				node = base_Node(k, null);
				node.children = new Bswabe_Policy[n];

			  	for (i = n - 1; i >= 0; i--)
					node.children[i] = stack.remove(stack.size() - 1);

				/* push result */
				stack.add(node);
			}
                        
                        
		}

		if (stack.size() > 1) {
			System.out.println("error parsing " + s
					+ ": extra node left on the stack");
			return null;
		} else if (stack.size() < 1) {
			System.out.println("error parsing " + s + ": empty policy");
			return null;
		}

		root = stack.get(0);
                System.out.println("end of parse policy");
		return root;
	}
            private static Bswabe_Policy base_Node(int k, String s) {
		Bswabe_Policy p = new Bswabe_Policy();

		p.k = k;
		if (!(s == null))
			p.attr = s;
		else
			p.attr = null;
		p.q = null;

		return p;
	}
    }
class enc_h_s extends Ciphertext implements Runnable
{
public void run()
{
    
 //       System.out.println("pa in h_S"+pa);
 //  System.out.println("s in h_s"+s); 
	cph.c = pa.getG1().newElement(); 
        
        cph.c=pub.h.duplicate();
        cph.c.powZn(s);
}
}
      //     System.out.println("**************************ENCRYPTION******************************");
      //  System.out.println("value of s is");
     //   System.out.println(s);
        
     //   System.out.println("value of c to the power s is");
     //   System.out.println(cph.c);
        
        /*
        String message="abcdef";
        Scanner sc=new Scanner(System.in);
        int l=message.length();
        
        
        
      ct=new Integer[l];
      int i;
      for(i=0;i<l;i++)
      {
         ct[i]=(int)message.charAt(i);
      }
    
        */
class enc_m_g_alpha_s extends Ciphertext implements Runnable
{
public void run()
{       cph.cs = pa.getGT().newElement(); 
        m = pa.getGT().newElement();
        m.setToRandom();
        cph.cs=pub.g_hat_alpha.duplicate();
        cph.cs.powZn(s);
        cph.cs.mul(m);
}
}
        /*key=m;
     //    System.out.println("value of cs to the power s is");
     //   System.out.println(cs);
        ctext=new Element[l];
       for(i=0;i<l;i++)
      {
         ctext[i]=cs.mul(ct[i]);
      }
    //   System.out.println("elements of element array");
       for(i=0;i<l;i++)
       {
          // System.out.println(ctext[i]);
       }
        
        return s;
      */
class enc_fill_policy extends Ciphertext implements Runnable
{
public void run()
{
        try
        {
        //    System.out.println("value of s paased in fill policy"+s);
        fill_Policy(cph.p, pub, s);
        }
        catch(Exception e)
        {
            System.out.println("exception in fill policy");
        }
}
private static void fill_Policy(Bswabe_Policy p, Bswabe_Pub pub, Element e)
			throws NoSuchAlgorithmException {
		int i;
		Element r, t, h;
		Pairing pairing = pub.p;
		r = pairing.getZr().newElement();
		t = pairing.getZr().newElement();
		h = pairing.getG2().newElement();
           //     System.out.println("value of s before rand poly="+e);
		p.q = rand_Poly(p.k - 1, e);
                for(i=0;i<p.k;i++)
             //   System.out.println("attr="+p.attr+"q.coef["+i+"]"+p.q.coef[i]);
		if (p.children == null || p.children.length == 0) {
			p.c = pairing.getG1().newElement();
			p.cp = pairing.getG2().newElement();

			elementFromString(h, p.attr);
			p.c = pub.g.duplicate();
			p.c.powZn(p.q.coef[0]); 	
			p.cp = h.duplicate();
			p.cp.powZn(p.q.coef[0]);
		} else {
			for (i = 0; i < p.children.length; i++) {
				r.set(i + 1);
                             //   System.out.println("r="+r);
				eval_Poly(t, p.q, r);
				fill_Policy(p.children[i], pub, t);
			}
		}

	}

    private static Bswabe_Polynomial rand_Poly(int deg, Element zeroVal) {
		int i;
		Bswabe_Polynomial q = new Bswabe_Polynomial();
		q.deg = deg;
		q.coef = new Element[deg + 1];

		for (i = 0; i < deg + 1; i++)
                {q.coef[i] = zeroVal.duplicate();
                //System.out.println("init q.coef["+i+"]"+q.coef[i]);
                }

		q.coef[0].set(zeroVal);

		for (i = 1; i < deg + 1; i++)
                {q.coef[i].setToRandom();
                // System.out.println("final q.coef["+i+"]"+q.coef[i]);
                }

		return q;
	}
    
    private static void eval_Poly(Element r, Bswabe_Polynomial q, Element x) {
		int i;
		Element s, t;
            //    System.out.println("inside evaluate policy");
              //  for (i = 0; i < q.deg + 1; i++)
               // {
               //  System.out.println("final q.coef["+i+"]"+q.coef[i]);
              //  }
		s = r.duplicate();
		t = r.duplicate();

		r.setToZero();
		t.setToOne();

		for (i = 0; i < q.deg + 1; i++) {
			/* r += q->coef[i] * t */
			s = q.coef[i].duplicate();
			s.mul(t); 
			r.add(s);

			/* t *= x */
			t.mul(x);
                        
		}
             //   System.out.println("val of t inside eval poly="+r);

	}
private static void elementFromString(Element h, String s)
			throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] digest = md.digest(s.getBytes());
		h.setFromHash(digest, 0, digest.length);
	}
}
/*try
        {
            FileOutputStream fo=new  FileOutputStream("D:\\Workspace\\Java\\MyProject\\modified cpabe\\Mod Access str2");
            ObjectOutputStream ob=new ObjectOutputStream(fo);
           
           
            Queue<Bswabe_Policy> quew = new LinkedList<Bswabe_Policy>();
            Bswabe_Policy nodew = new Bswabe_Policy();
            nodew=cph.p;
             quew.add(nodew);
                      
               while(quew.size()>0)
               {
                 System.out.println("que size"+quew.size());
                 Bswabe_Policy nodew1 = new Bswabe_Policy();
                 nodew1=quew.remove();
                 ob.writeObject(nodew1);
                 System.out.println("ppppp");
          //       System.out.println ("node.x ="+node.x+  "node.y " + node.y) ;
                //wo.writeObj(nodew);
                 for(int i=nodew1.children.length;i>0;i--)
                {//System.out.println("inside fh loop");
                                       //System.out.println ("level ="+(j)+ "attr="+node.children[i].attr+"parent="+node.children[i].parent.attr+"parent x="+node.children[i].parent.x+ "x: " + node.children[i].x + " y: " + node.children[i].y + "  num: " + node.children[i].num + "  k:" + node.children[i].k + " attr: "+node.children[i].attr+" p.c: "+node.children[i].c+"  p.cp"+node.children[i].cp) ;
                   // iw=iw+ (int)(ObjectSizeFetcher.getObjectSize(nodew));
                   // System.out.println("size of str object="+iw);
                   quew.add(nodew1.children[i]); 
                }
                 
                }

            ob.close();
            fo.close();
        }
        catch(Exception e)
        {
            System.out.println("error in file stored");
        }
  */      

    
    /*Access_Policy access_structure(String Cipher_Policy)
    {
        String[] toks;
        String tok;
        ArrayList<Access_Policy>stack=new  ArrayList<>();
        toks=Cipher_Policy.split(" ");
        int index;
        index = toks.length;
        
        int i;
        
        for(i=0;i<index;i++)
        {
            int k,n;
            tok=toks[i];
            if(!tok.contains("of"))
            {
                Access_Policy node=new Access_Policy();
                node.attr=tok;
                node.k=1;
                stack.add(node);
                
                
               }
            else
            {
                String[]again=tok.split("of");
                k=Integer.parseInt(again[0]);
                n=Integer.parseInt(again[1]);
                Access_Policy node2=new Acces s_Policy();
                node2.attr=null;
                node2.k=k;
                node2.child=new Access_Policy[n];
                int it;
                for(it=n-1;it>=0;it--)
                {
                  
                    node2.child[it]=stack.remove(stack.size()-1);
                    
                    
                }
              
                stack.add(node2);
                
            }
        }
        p=stack.get(0);
       return p;
        
        
    }
    void Fill_Policy(Access_Policy p,Make_Setup m,Element e)
    {
        int i;
		Element r, t, h;
		Pairing pairing = m.p;
		r = pairing.getZr().newElement();
		t = pairing.getZr().newElement();
		h = pairing.getG2().newElement();
                h=m.h.duplicate();

		p.q = randPoly(p.k - 1, e);

		if (p.child == null || p.child.length == 0) {
			p.c1 = pairing.getG1().newElement();
			p.c2 = pairing.getG2().newElement();

			
			p.c1 = m.g.duplicate();;
			p.c1.powZn(p.q.coef[0]); 
                        try
                        {
                        elementFromString(h, p.attr);
                        }
                        catch(Exception ddd)
                        {
                        System.out.println("error");
                        }
			p.c2 = h.duplicate();
			p.c2.powZn(p.q.coef[0]);
		} else {
			for (i = 0; i < p.child.length; i++) {
				r.set(i + 1);
				Evaluate_Policy(t, p.q, r);
				Fill_Policy(p.child[i], m, t);
			}
		}

	}
    private static void elementFromString(Element h, String s)
			throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] digest = md.digest(s.getBytes());
		h.setFromHash(digest, 0, digest.length);
	}
    void Evaluate_Policy(Element r, Polynomial q, Element x) {
		int i;
		Element s, t;

		s = r.duplicate();
		t = r.duplicate();

		r.setToZero();
		t.setToOne();

		for (i = 0; i < q.degree + 1; i++) {
			
			s = q.coef[i].duplicate();
			s.mul(t); 
			r.add(s);

			
			t.mul(x);
		}

	}
     Polynomial randPoly(int deg, Element zeroVal) {
		int i;
		Polynomial q = new Polynomial();
		q.degree = deg;
		q.coef = new Element[deg + 1];

		for (i = 0; i < deg + 1; i++)
			q.coef[i] = zeroVal.duplicate();

		q.coef[0].set(zeroVal);

		for (i = 1; i < deg + 1; i++)
			q.coef[i].setToRandom();

		return q;
	}
    */
    



	


class Decryption
{
    /*void decrypt(Key_Generation sk,Access_Policy p)
    {
      
        
       

        if(p.attr!=null)
        {  
            
            int i=0;
            String at;
            at=p.attr;
          
            
            for(i=0;i<sk.comps.size();i++)
            {
                if(at.compareTo(sk.comps.get(i).attr)==0)
                {
                    p.satisfy=true;
                return;
                }
               
            }
            
        
        }
        else
        {
 
            int i;
             
              
             
            for(i=0;i<p.child.length;i++)
            {  
                
               
             
              decrypt(sk,p.child[i]);
            }
          
        }
        }
     
            
        
    
    boolean check(Access_Policy p)
    {
       
        int count=0;
        int i;
         
         
         for(i=0;i<p.child.length;i++)
         {
            if(p.child[i].satisfy==true)
            {
                count++;
            }
         }
         System.out.println(count);
         if(count>=p.k)
         {
             
             System.out.println("ACCESS GRANTED");
             return true;
         }
         else
         {
             
             System.out.println("ACCESS DENIED"); 
             return false;
         }
    }
         void getvalue(Ciphertext t,Key_Generation k,Make_Setup pub)
         {
         System.out.println("Working on fetching the decrypted value");
         System.out.println("The value of g to the power (alpha + r)/ beta is");
         System.out.println(k.d);
         System.out.println("The billenear map of h to the power s and g to the power (alpha + r)/ beta");
          
           Pairing pair;
           pair=pub.p;
          Element r1=pair.getG1().newElement();
          r1=k.d.duplicate();
            Element r2=pair.getG1().newElement();
            r2=t.c.duplicate();
              Element r3=pair.getGT().newElement();
              r3=pair.pairing(r1, r2);
              System.out.println(r3);
              System.out.println("divide the above obtained value with cs of cyphertext");
              r3.div(t.cs);
              System.out.println(r3);
          

}*/
    
    static Bswabe_Element_Boolean dec(Bswabe_Pub pub, Bswabe_Prv prv,
			Bswabe_Cph cph) {
		Element t;
		Element m;
		Bswabe_Element_Boolean beb = new Bswabe_Element_Boolean();

		m = pub.p.getGT().newElement();
		t = pub.p.getGT().newElement();

		checkSatisfy(cph.p, prv);
		if (!cph.p.satisfiable) {
			System.err.println("cannot decrypt, attributes in key do not satisfy policy");
			beb.e = null;
			beb.b = false;
			return beb;
		}

		pickSatisfyMinLeaves(cph.p, prv);
        //        System.out.println("value of t before decflatten"+t);
		decFlatten(t, cph.p, prv, pub);
          //      System.out.println("value of t after decflatten"+t);
		m = cph.cs.duplicate();
		m.mul(t); /* num_muls++; */

		t = pub.p.pairing(cph.c, prv.d);
		t.invert();
		m.mul(t); /* num_muls++; */
		beb.e = m;
		beb.b = true;

		return beb;
	}

	private static void decFlatten(Element r, Bswabe_Policy p, Bswabe_Prv prv,
			Bswabe_Pub pub) {
		Element one;
		one = pub.p.getZr().newElement();
		one.setToOne();
		r.setToOne();
            //    System.out.println("value of t inside decflatten"+r);
		decNodeFlatten(r, one, p, prv, pub);
	}

	private static void decNodeFlatten(Element r, Element exp, Bswabe_Policy p,
			Bswabe_Prv prv, Bswabe_Pub pub) {
		if (p.children == null || p.children.length == 0)
			decLeafFlatten(r, exp, p, prv, pub);
		else
			decInternalFlatten(r, exp, p, prv, pub);
	}

	private static void decLeafFlatten(Element r, Element exp, Bswabe_Policy p,
			Bswabe_Prv prv, Bswabe_Pub pub) {
		Bswabe_PrvComp c;
		Element s, t;
            //    System.out.println("leaf flatten: "+p.attr);
		c = prv.comps.get(p.attri);

		s = pub.p.getGT().newElement();
		t = pub.p.getGT().newElement();

		s = pub.p.pairing(p.c, c.d); /* num_pairings++; */
		t = pub.p.pairing(p.cp, c.dp); /* num_pairings++; */
		t.invert();
		s.mul(t); /* num_muls++; */
		s.powZn(exp); /* num_exps++; */

		r.mul(s); /* num_muls++; */
	}

	private static void decInternalFlatten(Element r, Element exp,
			Bswabe_Policy p, Bswabe_Prv prv, Bswabe_Pub pub) {
		int i;
		Element t, expnew;
            //    System.out.println("internal flatten: "+p.attr);
            //    System.out.println("value of t inside decInternal"+r);
		t = pub.p.getZr().newElement();
		expnew = pub.p.getZr().newElement();

		for (i = 0; i < p.satl.size(); i++) {
              //      System.out.println("p.sat1: "+p.satl);
			lagrangeCoef(t, p.satl, (p.satl.get(i)).intValue());
			expnew = exp.duplicate();
			expnew.mul(t);
			decNodeFlatten(r, expnew, p.children[p.satl.get(i) - 1], prv, pub);
		}
	}

	private static void lagrangeCoef(Element r, ArrayList<Integer> s, int i) {
		int j, k;
		Element t;
                //System.out.println("lagrange...."+"r="+r+"s="+s+"i="+i);
		t = r.duplicate();

		r.setToOne();
		for (k = 0; k < s.size(); k++) {
			j = s.get(k).intValue();
			if (j == i)
				continue;
			t.set(-j);
			r.mul(t); /* num_muls++; */
			t.set(i - j);
			t.invert();
			r.mul(t); /* num_muls++; */
		}
	}

	private static void pickSatisfyMinLeaves(Bswabe_Policy p, Bswabe_Prv prv) {
		int i, k, l, c_i;
		int len;
               // System.out.println("attr="+p.attr);
                //System.out.println("q.coef[0]"+p.q.coef[0]);
               // System.out.println("p.children.length"+p.children.length);
		ArrayList<Integer> c = new ArrayList<Integer>();

		if (p.children == null || p.children.length == 0)
                {	p.min_leaves = 1;
                 //       System.out.println("min leaves="+p.min_leaves);
                }
		else { // System.out.println("p.children.length"+p.children.length);
			len = p.children.length;
			for (i = 0; i < len; i++)
				if (p.children[i].satisfiable)
                                {
				//System.out.println("attr="+p.attr);	
                                pickSatisfyMinLeaves(p.children[i], prv);
                                     
                                }

			for (i = 0; i < len; i++)
                        {
				c.add(new Integer(i));
                        }
                       // for (i = 0; i < c.size(); i++)
                       // {
			//	System.out.println("element of c="+c.get(i));
                        //}
			Collections.sort(c, new IntegerComparator(p));
                       // System.out.println("sorted element of c");
                        for (i = 0; i < c.size(); i++)
                        {
			//	System.out.println("element of c="+c.get(i));
                        }
			p.satl = new ArrayList<Integer>();
			p.min_leaves = 0;
			l = 0;

			for (i = 0; i < len && l < p.k; i++) {
                                
				c_i = c.get(i).intValue(); /* c[i] */
                          //      System.out.println("c_i"+c_i);
				if (p.children[c_i].satisfiable) {
					l++;
                            //            System.out.println("p.min_leaves"+p.min_leaves);
                            //            System.out.println("p.children[c_i].min_leaves"+p.children[c_i].min_leaves);
					p.min_leaves += p.children[c_i].min_leaves;
                              //          System.out.println("p.min_leaves"+p.min_leaves);
					k = c_i + 1;
                                //        System.out.println("k="+k);
					p.satl.add(new Integer(k));
				}
			}
                        //for (i = 0; i < p.satl.size(); i++)
                        //{
			//	System.out.println("p.attr"+p.attr+"element of p.sat="+p.satl.get(i));
                        //}
		}
	}

	private static void checkSatisfy(Bswabe_Policy p, Bswabe_Prv prv) {
		int i, l;
		String prvAttr;

		p.satisfiable = false;
		if (p.children == null || p.children.length == 0) {
			for (i = 0; i < prv.comps.size(); i++) {
				prvAttr = prv.comps.get(i).attr;
				// System.out.println("prvAtt:" + prvAttr);
				// System.out.println("p.attr" + p.attr);
				if (prvAttr.compareTo(p.attr) == 0) {
					// System.out.println("=staisfy=");
					p.satisfiable = true;
					p.attri = i;
					break;
				}
			}
		} else {
			for (i = 0; i < p.children.length; i++)
				checkSatisfy(p.children[i], prv);

			l = 0;
			for (i = 0; i < p.children.length; i++)
				if (p.children[i].satisfiable)
					l++;

			if (l >= p.k)
				p.satisfiable = true;
		}
	}
}
class IntegerComparator implements Comparator<Integer> {
		Bswabe_Policy policy;

		public IntegerComparator(Bswabe_Policy p) {
			this.policy = p;
		}

		@Override
		public int compare(Integer o1, Integer o2) {
			int k, l;

			k = policy.children[o1.intValue()].min_leaves;
			l = policy.children[o2.intValue()].min_leaves;

			return	k < l ? -1 : 
					k == l ? 0 : 1;
		}
	}    

class Lang_Policy {

	public static String[] parseAttribute(String s) {
		ArrayList<String> str_arr = new ArrayList<String>();
		StringTokenizer st = new StringTokenizer(s);
		String token;
		String res[];
		int len;

		while (st.hasMoreTokens()) {
			token = st.nextToken();
			if (token.contains(":")) {
				str_arr.add(token);
			} else {
				System.out.println("Some error happens in the input attribute");
				System.exit(0);
			}
		}

		Collections.sort(str_arr, new SortByAlphabetic());

		len = str_arr.size();
		res = new String[len];
		for (int i = 0; i < len; i++)
			res[i] = str_arr.get(i);
		return res;
	}

	/*public static void main(String[] args) {
		String attr = "objectClass:inetOrgPerson objectClass:organizationalPerson "
				+ "sn:student2 cn:student2 uid:student2 userPassword:student2 "
				+ "ou:idp o:computer mail:student2@sdu.edu.cn title:student";
		String[] arr = parseAttribute(attr);
		for (int i = 0; i < arr.length; i++)
			System.out.println(arr[i]);
	}*/

	static class SortByAlphabetic implements Comparator<String> {
		@Override
		public int compare(String s1, String s2) {
			if (s1.compareTo(s2) >= 0)
				return 1;
			return 0;
		}

	}
}

public class OOM_CP_ABE {

    /**
     * @param args the command line arguments
     */
    public void setup(String pubfile, String mskfile) throws Exception,
			ClassNotFoundException {
		byte[] pub_byte, msk_byte;
		Bswabe_Pub pub = new Bswabe_Pub();
		Bswabe_Msk msk = new Bswabe_Msk();
                Make_Setup ms=new Make_Setup();
		ms.setup(pub, msk);

		/* store BswabePub into mskfile */
		pub_byte = Serialize_Utils.serializeBswabePub(pub);
		Cpabe_Common.spitFile(pubfile, pub_byte);

		/* store BswabeMsk into mskfile */
		msk_byte = Serialize_Utils.serializeBswabeMsk(msk);
		Cpabe_Common.spitFile(mskfile, msk_byte);
	}

	public void keygen(String pubfile, String prvfile, String mskfile,
			String attr_str) throws NoSuchAlgorithmException, Exception {
		Bswabe_Pub pub;
		Bswabe_Msk msk;
		byte[] pub_byte, msk_byte, prv_byte;

		/* get BswabePub from pubfile */
		pub_byte = Cpabe_Common.suckFile(pubfile);
		pub = Serialize_Utils.unserializeBswabePub(pub_byte);

		/* get BswabeMsk from mskfile */
		msk_byte = Cpabe_Common.suckFile(mskfile);
		msk = Serialize_Utils.unserializeBswabeMsk(pub, msk_byte);
                Key_Generation kg= new Key_Generation();
                String[] attr_arr=null;
                try
                {
		attr_arr = Lang_Policy.parseAttribute(attr_str);
                }
                catch(Exception e)
                {
                    System.out.println("lang policy error in key generation");
                }
		Bswabe_Prv prv = kg.secretkey(pub, msk, attr_arr);
                /* store BswabePrv into prvfile */
		prv_byte = Serialize_Utils.serializeBswabePrv(prv);
		Cpabe_Common.spitFile(prvfile, prv_byte);
	}

	public void enc(String pubfile, String policy, String inputfile,
			String encfile) throws Exception {
		Bswabe_Pub pub;
		Bswabe_Cph cph;
		Bswabe_CphKey keyCph;
		byte[] plt=null;
		byte[] cphBuf;
		byte[] aesBuf=null;
		byte[] pub_byte;
		Element m;

		/* get BswabePub from pubfile */
		pub_byte = Cpabe_Common.suckFile(pubfile);
		pub = Serialize_Utils.unserializeBswabePub(pub_byte);
             //   Ciphertext ct = new Ciphertext();
                enc_init_set eic=new enc_init_set(pub, policy);
                
                enc_parse_policy epp=new enc_parse_policy();
                enc_h_s ehs =new enc_h_s();
                enc_m_g_alpha_s emgas =new enc_m_g_alpha_s();
                 enc_fill_policy efp=new enc_fill_policy();
		//System.out.println("enc_init_complete");
                Thread e1 =new Thread (epp);
                Thread e2 =new Thread (ehs);
                Thread e3 =new Thread (emgas);
               Thread e4 =new Thread (efp);
                
                
                e2.start();
                e3.start();
                
               
                e1.start();
                e1.join();
                e4.start();
                e4.join();
                keyCph = eic.set_cph_key();
                cph = keyCph.cph;
		m = keyCph.key;
              //  System.out.println("m at enc="+m);
//		System.out.println("m = " + m.toString());

		if (cph == null) {
			System.out.println("Error happed in enc");
			System.exit(0);
		}

		cphBuf = Serialize_Utils.bswabeCphSerialize(cph);

		/* read file to encrypted */
                try
                {
		plt = Cpabe_Common.suckFile(inputfile);
                 }
                catch(Exception e)
                {
                    System.out.println("Exception in suck input");
                }
                long ets1=System.currentTimeMillis();
                try
                {
		aesBuf = AESCode.encrypt(m.toBytes(), plt);
              //  System.out.println("aesbuf="+aesBuf);
                 }
                catch(Exception e)
                {
                    System.out.println("Exception in aes enc");
                }
                
                long ets2=System.currentTimeMillis();
                System.out.println("symmetric encryption time="+(ets2-ets1));
                try
                {
             
		Cpabe_Common.writeCpabeFile(encfile, cphBuf, aesBuf);
                }
                catch(Exception e)
                {
                    System.out.println("Exception in write");
                }
		// PrintArr("element: ", m.toBytes());
                
	}

	public void dec(String pubfile, String prvfile, String encfile,
			String decfile) throws Exception {
		byte[] aesBuf, cphBuf;
		byte[] plt;
		byte[] prv_byte;
		byte[] pub_byte;
		byte[][] tmp=null;
		Bswabe_Cph cph;
		Bswabe_Prv prv;
		Bswabe_Pub pub;

		/* get BswabePub from pubfile */
                
		pub_byte = Cpabe_Common.suckFile(pubfile);
		//System.out.println("decryption function");
pub = Serialize_Utils.unserializeBswabePub(pub_byte);
		/* read ciphertext */
                try
                {
		tmp = Cpabe_Common.readCpabeFile(encfile);
                }
                catch(Exception e)
                {
                    System.out.println("exception in reading enc file");
                }
                
		aesBuf = tmp[0];
		cphBuf = tmp[1];
		cph = Serialize_Utils.bswabeCphUnserialize(pub, cphBuf);
                
             //  System.out.println("aesbuf in reAD="+aesBuf);

		/* get BswabePrv form prvfile */
		prv_byte = Cpabe_Common.suckFile(prvfile);
		prv = Serialize_Utils.unserializeBswabePrv(pub, prv_byte);
               // System.out.println("decryption function........1");
                Decryption dc = new Decryption();
               // System.out.println("decryption function........2");
		Bswabe_Element_Boolean beb = dc.dec(pub, prv, cph);
               // System.out.println("decryption function........3");
		System.err.println("e = " + beb.e.toString());
		if (beb.b) {
                 //   System.out.println("decryption function........4");
                    System.out.println("m at dec="+beb.e);
                    long etd1=System.currentTimeMillis();
			plt = AESCode.decrypt(beb.e.toBytes(), aesBuf);
                        long etd2=System.currentTimeMillis();
                        System.out.println("symmetric decryption time="+(etd2-etd1));
			Cpabe_Common.spitFile(decfile, plt);
		} else {
			System.exit(0);
		}
	}

    
   /* public static void main(String[] args)throws IOException {
        // TODO code application logic here
       String str="abcd"; 
        byte[] plt =str.getBytes();
		byte[] cphBuf;
		byte[] aesBuf=null;
                Element m;
                
        Make_Setup ob=new Make_Setup();
       long time1;
       time1=System.currentTimeMillis();
       ob.setup();
       long time2=System.currentTimeMillis();
        System.out.println("time for setup in milli seconds");
       System.out.println(time2-time1);
       Access_Policy root;
       
       Key_Generation key=new Key_Generation();
       long keygentime1;
        keygentime1 =System.currentTimeMillis();
       key.secretkey(ob);
        long keygentime2;
        keygentime2 =System.currentTimeMillis();
        System.out.println("time for key generation in milli seconds");
       System.out.println(keygentime2-keygentime1);
       Ciphertext text=new Ciphertext();
       long enc1=System.currentTimeMillis();
       Element s_p=text.generate_ct(ob);
       long enc12=System.currentTimeMillis();
       
      
       System.out.println(s_p);
       Scanner sc=new Scanner(System.in);
       System.out.println("enter the cypher policy");
       String s=sc.nextLine();
        long enc2=System.currentTimeMillis();
       text.p=text.access_structure(s);
       System.out.println(text.p.k);
       long enc22=System.currentTimeMillis();
       long enc3=System.currentTimeMillis();
       text.Fill_Policy(text.p, ob, s_p);
       try
       {
       plt = Common.suckFile("abc");
       }
       catch(Exception e){
       System.out.println("error in read file");
       }
       
       m = text.key.duplicate();
       
       System.out.println(".................m="+m);
       try
       {System.out.println("befor encr str ="+str);
           System.out.println("befor encr="+plt);
        aesBuf = AESCode.encrypt(m.toBytes(), plt);
        System.out.println("after encr="+aesBuf);
       }
       catch(Exception e){
       System.out.println("error in encryption");
       }
       long enc32=System.currentTimeMillis();
       int i;
       System.out.println("time for encryption");
       System.out.println((enc12-enc1)+(enc22-enc2)+(enc32-enc3));
   
     Decryption d1=new Decryption();
     long dect=System.currentTimeMillis();
     d1.decrypt(key,text.p);
          
     boolean x;
     
     x=d1.check(text.p);
     if(x)
     {
          
         d1.getvalue(text,key,ob);
         try
         {
         plt = AESCode.decrypt(m.toBytes(),aesBuf);
         
         System.out.println("decrypted data="+plt);
         }
         catch(Exception e){ System.out.println("error in decryption");}
     }
      long fdect=System.currentTimeMillis();
       System.out.println("time for decryption");
      System.out.println(fdect-dect);

  */
   
	final static boolean DEBUG = true;

	//static String dir = "demo/cpabe";

    static String pubfile =  "D:\\Workspace\\Java\\MyProject\\modified cpabe\\pub_key";
	static String mskfile =  "D:\\Workspace\\Java\\MyProject\\modified cpabe\\master_key";
	static String prvfile =  "D:\\Workspace\\Java\\MyProject\\modified cpabe\\prv_key";

	static String inputfile =  "D:\\Workspace\\Java\\MyProject\\modified cpabe\\pp.txt";
	static String encfile = "D:\\Workspace\\Java\\MyProject\\modified cpabe\\pp19.txt.cpabe";
	static String decfile = "D:\\Workspace\\Java\\MyProject\\modified cpabe\\ppx1902.txt.dec";
 public static void main(String[] args) throws Exception {
		String attr_str, policy;
		// attr = attr_kevin;
		// attr = attr_sara;
		// policy = policy_kevin_or_sara;
		//attr_str = array2Str(attr);
              /* String student_attr = "objectClass:inetOrgPerson objectClass:organizationalPerson "
			+ "sn:student2 cn:student2 uid:student2 userPassword:student2 "
			+ "ou:idp o:computer mail:student2@sdu.edu.cn title:student";

	String student_policy = "sn:student2 cn:student2 uid:student2 3of3";*/
            //   String student_attr = "c:car r:res ap:attphy";
            
            
            
     //1    String student_attr = "c:car r:res";
     //   String student_policy = "c:car r:res 2of2";
        
    //2     String student_attr = "c:car r:res p:pes";
   //      String student_policy = "c:car r:res 2of2 p:pes 2of2"; 
        
	//3 String student_attr = "c:car r:res p:pes q:qes";
       //  String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2";
        
  
    //4     String student_attr = "c:car r:res p:pes q:qes a:aes";
    //     String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2";
        
    //5     String student_attr = "c:car r:res p:pes q:qes a:aes b:bes";
    //     String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2";
        
    //6     String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces";
    //     String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2";
        
    //7    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des";
    //    String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2";
        
    //8    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees";
    //    String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2";
        
    //9    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes";
    //     String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2";
        
    //10    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges";
    //    String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2";
        
    //11    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes";
    //    String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2";
        
    //12    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies";
    //    String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2";
        
    //13    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes";
    //    String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2";
        
    //14    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes";
   //     String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2";
        
     //15  String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes l:les";
     //   String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2";
        
     //16   String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes l:les m:mes";
    //  String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2 m:mes 2of2";
        
    //17    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes l:les m:mes n:nes";
    //   String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2 m:mes 2of2 n:nes 2of2";
        
    //18    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes l:les m:mes n:nes o:oes";
    //    String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2 m:mes 2of2 n:nes 2of2 o:oes 2of2";
        
    //19    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes l:les m:mes n:nes o:oes z:zes";
    //   String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2 m:mes 2of2 n:nes 2of2 o:oes 2of2 z:zes 2of2";
        
    //20    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes l:les m:mes n:nes o:oes z:zes q:qes";
   //     String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2 m:mes 2of2 n:nes 2of2 o:oes 2of2 z:zes 2of2 q:qes 2of2";
        
    //21    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes l:les m:mes n:nes o:oes z:zes q:qes r:res";
    //    String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2 m:mes 2of2 n:nes 2of2 o:oes 2of2 z:zes 2of2 q:qes 2of2 r:res 2of2";
        
    //22    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes l:les m:mes n:nes o:oes z:zes q:qes r:res s:ses";
    //    String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2 m:mes 2of2 n:nes 2of2 o:oes 2of2 z:zes 2of2 q:qes 2of2 r:res 2of2 s:ses 2of2";
        
    //23    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes l:les m:mes n:nes o:oes z:zes q:qes r:res s:ses t:tes";
    //    String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2 m:mes 2of2 n:nes 2of2 o:oes 2of2 z:zes 2of2 q:qes 2of2 r:res 2of2 s:ses 2of2 t:tes 2of2";
        
        
    //24    String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes l:les m:mes n:nes o:oes z:zes q:qes r:res s:ses t:tes u:ues v:ves";
    //    String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2 m:mes 2of2 n:nes 2of2 o:oes 2of2 z:zes 2of2 q:qes 2of2 r:res 2of2 s:ses 2of2 t:tes 2of2 u:ues 2of2 v:ves 2of2";
        
         String student_attr = "c:car r:res p:pes q:qes a:aes b:bes c:ces d:des e:ees f:fes g:ges h:hes i:ies j:jes k:kes l:les m:mes n:nes o:oes z:zes q:qes r:res s:ses t:tes u:ues v:ves w:wes";
     String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2 m:mes 2of2 n:nes 2of2 o:oes 2of2 z:zes 2of2 q:qes 2of2 r:res 2of2 s:ses 2of2 t:tes 2of2 u:ues 2of2 v:ves 2of2 w:wes 2of2";

        
//String student_policy = "c:car r:res 2of2 ap:attphy 2of2";
       
       // String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 r:res 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2 g:ges 2of2 h:hes 2of2 i:ies 2of2 j:jes 2of2 k:kes 2of2 l:les 2of2 m:mes 2of2 n:nes 2of2 o:oes 2of2 p:pes 2of2 q:qes 2of2 r:res 2of2 s:ses 2of2 t:tes 2of2 u:ues 2of2 v:ves 2of2";
       // String student_policy = "c:car r:res 2of2 p:pes 2of2 q:qes 2of2 r:res 2of2 a:aes 2of2 b:bes 2of2 c:ces 2of2 d:des 2of2 e:ees 2of2 f:fes 2of2";
		
                attr_str = student_attr;
		policy = student_policy;

		OOM_CP_ABE test = new OOM_CP_ABE();
		println("//start to setup");
                long etst1=System.currentTimeMillis();
		test.setup(pubfile, mskfile);
                long etst2=System.currentTimeMillis();
                System.out.println("setup cost="+(etst2-etst1));
		println("//end to setup");

		println("//start to keygen");
                long etk1=System.currentTimeMillis();
                try
                {
		test.keygen(pubfile, prvfile, mskfile, attr_str);
                }
                catch(Exception e)
                {
                System.out.println("error in test.keygen");
                }
		println("//end to keygen");
                long etk2=System.currentTimeMillis();
                System.out.println("key generation time="+(etk2-etk1));

		println("//start to enc");
                long et1=System.currentTimeMillis();
		test.enc(pubfile, policy, inputfile, encfile);
                long et2=System.currentTimeMillis();
                System.out.println("encryption time="+(et2-et1));
		println("//end to enc");

		println("//start to dec");
                long dt1=System.currentTimeMillis();
		test.dec(pubfile, prvfile, encfile, decfile);
                long dt2=System.currentTimeMillis();
                System.out.println("dec time="+(dt2-dt1));
		println("//end to dec");
	}

	/* connect element of array with blank */
	public static String array2Str(String[] arr) {
		int len = arr.length;
		String str = arr[0];

		for (int i = 1; i < len; i++) {
			str += " ";
			str += arr[i];
		}

		return str;
	}

	private static void println(Object o) {
		if (DEBUG)
			System.out.println(o);
	}
       
       
   
    
}
class AESCode {

	private static byte[] getRawKey(byte[] seed) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(seed);
		kgen.init(128, sr); // 192 and 256 bits may not be available
		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();
		return raw;
	}

	public static byte[] encrypt(byte[] seed, byte[] plaintext)
			throws Exception {
		byte[] raw = getRawKey(seed);
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		byte[] encrypted = cipher.doFinal(plaintext);
		return encrypted;
	}

	public static byte[] decrypt(byte[] seed, byte[] ciphertext)
			throws Exception {
		byte[] raw = getRawKey(seed);
                
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec);
              //  System.out.println("decryption function.......aes");
                byte[] decrypted=null;
                
		decrypted = cipher.doFinal(ciphertext);
                
                
		return decrypted;
	}

}


class Cpabe_Common {

	/* read byte[] from inputfile */
	public static byte[] suckFile(String inputfile) throws Exception {
		InputStream is = new FileInputStream(inputfile);
                //System.out.println(is.canRead()+"bhbbj");
		int size = is.available();
         //       System.out.println("Size="+size+","+inputfile);
		byte[] content = new byte[size];

		is.read(content);

		is.close();
		return content;
	}

	/* write byte[] into outputfile */
	public static void spitFile(String outputfile, byte[] b) throws Exception {
		OutputStream os = new FileOutputStream(outputfile);
		os.write(b);
		os.close();
	}


	public static void writeCpabeFile(String encfile,
			byte[] cphBuf, byte[] aesBuf) throws Exception {
		int i;
		OutputStream os = new FileOutputStream(encfile);

		/* write aes_buf */
		for (i = 3; i >= 0; i--)
			os.write(((aesBuf.length & (0xff << 8 * i)) >> 8 * i));
		os.write(aesBuf);

		/* write cph_buf */
		for (i = 3; i >= 0; i--)
			os.write(((cphBuf.length & (0xff << 8 * i)) >> 8 * i));
		os.write(cphBuf);

		os.close();

	}

	public static byte[][] readCpabeFile(String encfile) throws Exception {
		int i, len;
		InputStream is = new FileInputStream(encfile);
		byte[][] res = new byte[2][];
		byte[] aesBuf, cphBuf;

		/* read aes buf */
		len = 0;
		for (i = 3; i >= 0; i--)
			len |= is.read() << (i * 8);
		aesBuf = new byte[len];

		is.read(aesBuf);
              //  System.out.println("length of aesbuf="+len);
		/* read cph buf */
		len = 0;
		for (i = 3; i >= 0; i--)
			len |= is.read() << (i * 8);
		cphBuf = new byte[len];
            //    System.out.println("length of cphbuf="+len);
		is.read(cphBuf);

		is.close();

		res[0] = aesBuf;
		res[1] = cphBuf;
		return res;
	}
	/**
	 * Return a ByteArrayOutputStream instead of writing to a file
	 */
	public static ByteArrayOutputStream writeCpabeData(byte[] mBuf,
			byte[] cphBuf, byte[] aesBuf) throws Exception {
		int i;
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		/* write m_buf */
		for (i = 3; i >= 0; i--)
			os.write(((mBuf.length & (0xff << 8 * i)) >> 8 * i));
		os.write(mBuf);

		/* write aes_buf */
		for (i = 3; i >= 0; i--)
			os.write(((aesBuf.length & (0xff << 8 * i)) >> 8 * i));
		os.write(aesBuf);

		/* write cph_buf */
		for (i = 3; i >= 0; i--)
			os.write(((cphBuf.length & (0xff << 8 * i)) >> 8 * i));
		os.write(cphBuf);

		os.close();
		return os;
	}
	/**
	 * Read data from an InputStream instead of taking it from a file.
	 */
	public static byte[][] readCpabeData(InputStream is) throws Exception {
		int i, len;
		
		byte[][] res = new byte[3][];
		byte[] mBuf, aesBuf, cphBuf;

		/* read m buf */
		len = 0;
		for (i = 3; i >= 0; i--)
			len |= is.read() << (i * 8);
		mBuf = new byte[len];
		is.read(mBuf);
		/* read aes buf */
		len = 0;
		for (i = 3; i >= 0; i--)
			len |= is.read() << (i * 8);
		aesBuf = new byte[len];
		is.read(aesBuf);

		/* read cph buf */
		len = 0;
		for (i = 3; i >= 0; i--)
			len |= is.read() << (i * 8);
		cphBuf = new byte[len];
		is.read(cphBuf);

		is.close();
		res[0] = aesBuf;
		res[1] = cphBuf;
		res[2] = mBuf;
		return res;
	}
}
class delegate_key
{
 public static Bswabe_Prv delegate(Bswabe_Pub pub, Bswabe_Prv prv_src, String[] attrs_subset)
            throws NoSuchAlgorithmException, IllegalArgumentException {

            Bswabe_Prv prv = new Bswabe_Prv();
            Element g_rt, rt, f_at_rt;
            Pairing pairing;

            /* initialize */
            pairing = pub.p;
            prv.d = pairing.getG2().newElement();

            g_rt = pairing.getG2().newElement();
            rt = pairing.getZr().newElement();
            f_at_rt = pairing.getZr().newElement();

            /* compute */
            rt.setToRandom();
            f_at_rt = pub.f.duplicate();
            f_at_rt.powZn(rt);
            prv.d = prv_src.d.duplicate();
            prv.d.mul(f_at_rt);

            g_rt = pub.g.duplicate();
            g_rt.powZn(rt);

            int i, len = attrs_subset.length;
            //prv.comps = new ArrayList<Bswabe_PrvComp>();
            prv.comps = new ArrayList<Bswabe_PrvComp>();

            for (i = 0; i < len; i++) {
                Bswabe_PrvComp comp = new Bswabe_PrvComp();
                Element h_rtp;
                Element rtp;

                comp.attr = attrs_subset[i];

                Bswabe_PrvComp comp_src = new Bswabe_PrvComp();
                boolean comp_src_init = false;

                for (int j = 0; j < prv_src.comps.size(); ++j) {
                    if (prv_src.comps.get(j).attr == comp.attr) {
                        comp_src = prv_src.comps.get(j);
                        comp_src_init = true;
                        break;
                    }
                }

                if (comp_src_init == false) {
                    throw new IllegalArgumentException("comp_src_init == false");
                }

                comp.d = pairing.getG2().newElement();
                comp.dp = pairing.getG1().newElement();
                h_rtp = pairing.getG2().newElement();
                rtp = pairing.getZr().newElement();
                try
                {
                elementFromString(h_rtp, comp.attr);
                }
                catch(Exception e)
                {
                    System.out.println(e.getMessage());
                }
                rtp.setToRandom();

                h_rtp.powZn(rtp);

                comp.d = g_rt.duplicate();
                comp.d.mul(h_rtp);
                comp.d.mul(comp_src.d);

                comp.dp = pub.g.duplicate();
                comp.dp.powZn(rtp); 
                comp.dp.mul(comp_src.dp);
                

                prv.comps.add(comp);
            }

            return prv;
        }
 private static void elementFromString(Element h, String s)
			throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] digest = md.digest(s.getBytes());
		h.setFromHash(digest, 0, digest.length);
	}

    }

class Serialize_Utils {

	/* Method has been test okay */
	public static void serializeElement(ArrayList<Byte> arrlist, Element e) {
		byte[] arr_e = e.toBytes();
		serializeUint32(arrlist, arr_e.length);
		byteArrListAppend(arrlist, arr_e);
	}

	/* Method has been test okay */
	public static int unserializeElement(byte[] arr, int offset, Element e) {
		int len;
		int i;
		byte[] e_byte;

		len = unserializeUint32(arr, offset);
		e_byte = new byte[(int) len];
		offset += 4;
		for (i = 0; i < len; i++)
			e_byte[i] = arr[offset + i];
		e.setFromBytes(e_byte);

		return (int) (offset + len);
	}

	public static void serializeString(ArrayList<Byte> arrlist, String s) {
		byte[] b = s.getBytes();
		serializeUint32(arrlist, b.length);
		byteArrListAppend(arrlist, b);
	}

	/*
	 * Usage:
	 * 
	 * StringBuffer sb = new StringBuffer("");
	 * 
	 * offset = unserializeString(arr, offset, sb);
	 * 
	 * String str = sb.substring(0);
	 */
	public static int unserializeString(byte[] arr, int offset, StringBuffer sb) {
		int i;
		int len;
		byte[] str_byte;
	
		len = unserializeUint32(arr, offset);
		offset += 4;
		str_byte = new byte[len];
		for (i = 0; i < len; i++)
			str_byte[i] = arr[offset + i];
	
		sb.append(new String(str_byte));
		return offset + len;
	}

	public static byte[] serializeBswabePub(Bswabe_Pub pub) {
		ArrayList<Byte> arrlist = new ArrayList<Byte>();
	
		serializeString(arrlist, pub.pairingDesc);
		serializeElement(arrlist, pub.g);
		serializeElement(arrlist, pub.h);
		serializeElement(arrlist, pub.gp);
		serializeElement(arrlist, pub.g_hat_alpha);
	
		return Byte_arr2byte_arr(arrlist);
	}

	public static Bswabe_Pub unserializeBswabePub(byte[] b) {
		Bswabe_Pub pub;
		int offset;
	
		pub = new Bswabe_Pub();
		offset = 0;
	
		StringBuffer sb = new StringBuffer("");
		offset = unserializeString(b, offset, sb);
		pub.pairingDesc = sb.substring(0);
                
          

	PropertiesParameters params = new PropertiesParameters()
			.load(new ByteArrayInputStream(pub.pairingDesc.getBytes()));
	
		//CurveParameters params = new DefaultCurveParameters()
		//		.load(new ByteArrayInputStream(pub.pairingDesc.getBytes()));
		pub.p = PairingFactory.getPairing(params);
		Pairing pairing = pub.p;
	
		pub.g = pairing.getG1().newElement();
		pub.h = pairing.getG1().newElement();
		pub.gp = pairing.getG2().newElement();
		pub.g_hat_alpha = pairing.getGT().newElement();
	
		offset = unserializeElement(b, offset, pub.g);
		offset = unserializeElement(b, offset, pub.h);
		offset = unserializeElement(b, offset, pub.gp);
		offset = unserializeElement(b, offset, pub.g_hat_alpha);
	
		return pub;
	}

	/* Method has been test okay */
        
	public static byte[] serializeBswabeMsk(Bswabe_Msk msk) {
		ArrayList<Byte> arrlist = new ArrayList<Byte>();
	
		serializeElement(arrlist, msk.beta);
		serializeElement(arrlist, msk.g_alpha);
	
		return Byte_arr2byte_arr(arrlist);
	}

	/* Method has been test okay */
	public static Bswabe_Msk unserializeBswabeMsk(Bswabe_Pub pub, byte[] b) {
		int offset = 0;
		Bswabe_Msk msk = new Bswabe_Msk();
	
		msk.beta = pub.p.getZr().newElement();
		msk.g_alpha = pub.p.getG2().newElement();
	
		offset = unserializeElement(b, offset, msk.beta);
		offset = unserializeElement(b, offset, msk.g_alpha);
	
		return msk;
	}

	/* Method has been test okay */
	public static byte[] serializeBswabePrv(Bswabe_Prv prv) {
		ArrayList<Byte> arrlist;
		int prvCompsLen, i;
	
		arrlist = new ArrayList<Byte>();
		prvCompsLen = prv.comps.size();
		serializeElement(arrlist, prv.d);
		serializeUint32(arrlist, prvCompsLen);
	
		for (i = 0; i < prvCompsLen; i++) {
			serializeString(arrlist, prv.comps.get(i).attr);
			serializeElement(arrlist, prv.comps.get(i).d);
			serializeElement(arrlist, prv.comps.get(i).dp);
		}
	
		return Byte_arr2byte_arr(arrlist);
	}

	/* Method has been test okay */
	public static Bswabe_Prv unserializeBswabePrv(Bswabe_Pub pub, byte[] b) {
		Bswabe_Prv prv;
		int i, offset, len;
	
		prv = new Bswabe_Prv();
		offset = 0;
	
		prv.d = pub.p.getG2().newElement();
		offset = unserializeElement(b, offset, prv.d);
	
		prv.comps = new ArrayList<Bswabe_PrvComp>();
		len = unserializeUint32(b, offset);
		offset += 4;
	
		for (i = 0; i < len; i++) {
			Bswabe_PrvComp c = new Bswabe_PrvComp();
	
			StringBuffer sb = new StringBuffer("");
			offset = unserializeString(b, offset, sb);
			c.attr = sb.substring(0);
	
			c.d = pub.p.getG2().newElement();
			c.dp = pub.p.getG2().newElement();
	
			offset = unserializeElement(b, offset, c.d);
			offset = unserializeElement(b, offset, c.dp);
	
			prv.comps.add(c);
		}
	
		return prv;
	}

	public static byte[] bswabeCphSerialize(Bswabe_Cph cph) {
		ArrayList<Byte> arrlist = new ArrayList<Byte>();
		Serialize_Utils.serializeElement(arrlist, cph.cs);
		Serialize_Utils.serializeElement(arrlist, cph.c);
		serializePolicy(arrlist, cph.p);

		return Byte_arr2byte_arr(arrlist);
	}

	public static Bswabe_Cph bswabeCphUnserialize(Bswabe_Pub pub, byte[] cphBuf) {
		Bswabe_Cph cph = new Bswabe_Cph();
		int offset = 0;
		int[] offset_arr = new int[1];

		cph.cs = pub.p.getGT().newElement();
		cph.c = pub.p.getG1().newElement();

		offset = Serialize_Utils.unserializeElement(cphBuf, offset, cph.cs);
		offset = Serialize_Utils.unserializeElement(cphBuf, offset, cph.c);

		offset_arr[0] = offset;
		cph.p = unserializePolicy(pub, cphBuf, offset_arr);
		offset = offset_arr[0];

		return cph;
	}

	/* Method has been test okay */
	/* potential problem: the number to be serialize is less than 2^31 */
	private static void serializeUint32(ArrayList<Byte> arrlist, int k) {
		int i;
		byte b;
	
		for (i = 3; i >= 0; i--) {
			b = (byte) ((k & (0x000000ff << (i * 8))) >> (i * 8));
			arrlist.add(Byte.valueOf(b));
		}
	}

	/*
	 * Usage:
	 * 
	 * You have to do offset+=4 after call this method
	 */
	/* Method has been test okay */
	private static int unserializeUint32(byte[] arr, int offset) {
		int i;
		int r = 0;
	
		for (i = 3; i >= 0; i--)
			r |= (byte2int(arr[offset++])) << (i * 8);
		return r;
	}

	static void serializePolicy(ArrayList<Byte> arrlist, Bswabe_Policy p) {
		serializeUint32(arrlist, p.k);
	
		if (p.children == null || p.children.length == 0) {
			serializeUint32(arrlist, 0);
			serializeString(arrlist, p.attr);
			serializeElement(arrlist, p.c);
			serializeElement(arrlist, p.cp);
		} else {
			serializeUint32(arrlist, p.children.length);
			for (int i = 0; i < p.children.length; i++)
				serializePolicy(arrlist, p.children[i]);
		}
	}

	private static Bswabe_Policy unserializePolicy(Bswabe_Pub pub, byte[] arr,
			int[] offset) {
		int i;
		int n;
		Bswabe_Policy p = new Bswabe_Policy();
		p.k = unserializeUint32(arr, offset[0]);
		offset[0] += 4;
		p.attr = null;
	
		/* children */
		n = unserializeUint32(arr, offset[0]);
		offset[0] += 4;
		if (n == 0) {
			p.children = null;
	
			StringBuffer sb = new StringBuffer("");
			offset[0] = unserializeString(arr, offset[0], sb);
			p.attr = sb.substring(0);
	
			p.c = pub.p.getG1().newElement();
			p.cp = pub.p.getG1().newElement();
	
			offset[0] = unserializeElement(arr, offset[0], p.c);
			offset[0] = unserializeElement(arr, offset[0], p.cp);
		} else {
			p.children = new Bswabe_Policy[n];
			for (i = 0; i < n; i++)
				p.children[i] = unserializePolicy(pub, arr, offset);
		}
	
		return p;
	}

	private static int byte2int(byte b) {
		if (b >= 0)
			return b;
		return (256 + b);
	}

	private static void byteArrListAppend(ArrayList<Byte> arrlist, byte[] b) {
		int len = b.length;
		for (int i = 0; i < len; i++)
			arrlist.add(Byte.valueOf(b[i]));
	}

	private static byte[] Byte_arr2byte_arr(ArrayList<Byte> B) {
		int len = B.size();
		byte[] b = new byte[len];
	
		for (int i = 0; i < len; i++)
			b[i] = B.get(i).byteValue();
	
		return b;
	}

}




    
    

