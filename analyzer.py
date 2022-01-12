import networkx as nx
from itertools import chain
from itertools import product
from itertools import starmap
from functools import partial
import re


class analyzer:

    def __init__(self, dx, target_start, target_close):
        """This class is to analyze phyjack implementation flaws
        """
        self.dx = dx
        self.CG = dx.get_call_graph(no_isolated=True)
        self.target_start = target_start
        self.target_close = target_close

    def jackvul_analysis(self):
        """do analysis
        """
        print("\n[*] constructing call graph ...")
        print("number of CG edges: {}".format(self.CG.number_of_edges()))

        print("\n[*] finding using target method ...")
        exist_start = [item for item in self.target_start if self.is_exist_meth(classname=item[0], methodname=item[1])]
        if len(exist_start) == 0:
            print("target method NOT found in this apk!")
            # print("***this activity is NOT vulnerable!!!***")
            return ("no-call", [])

        start_cg = self.get_methodlist_cg(exist_start, outputchain=True)

        print("\n[*] finding root class in call chain of target method...")
        root_set = self.extract_rootset(start_cg)
        if(len(root_set) == 0):
            print("NO method call target method!")
            # print("***this activity is NOT vulnerable!!!***")
            return ("no-call", [])
        
        #searching any interfaces of close and build a close set
        print("\n[*] finding any interfaces of close ...")
        exist_close = [item for item in self.target_close if self.is_exist_meth(classname=item[0], methodname=item[1])]
        if len(exist_close) == 0:
            print("close method NOT found in this apk!")
            # print("***this activity is vulnerable!!!***")
            return ("never-cancel", [])
        
        close_set = set()
        for close_name in exist_close:
            mclose = self.find_method(close_name[0], close_name[1])
            mclose_set = self.get_close_interfaces(mclose)
            close_set.update(mclose_set)

        #judge existing chain root class if is any activity
        print("\n[*] search any activity found in call root ...")
        check_set = set()
        noact_set = set()
        for rootclass in root_set:
            self.check_class(rootclass, check_set, noact_set)
        print("found {} activity in {} call root class:".format(len(check_set), len(root_set)))
        for act in check_set:
            print("  "+act)
        
        #if not found activity in root class, search interfaces implemented by root class
        if len(check_set) == 0:
            check_set = self.check_noact_interface(start_cg, noact_set)

            if len(check_set) == 0:
                print("no any activity found in called or interface!")
                return ("no-activity-call", [])
        
        #can found activity in root class, checking activity
        print("\n[*] search onPause in found activity ...")
        vul_act = set()
        for call_act in check_set:
            if not self.check_act_onPause_close(call_act, close_set):
                vul_act.add(call_act)
        
        if len(vul_act) == 0:
            return ("correct-implement", [])
        else:
            return ("pause-failure", list(vul_act))

    
    def is_exist_meth(self, classname, methodname):
        """If a method can be found in APK.

        Args:
            classname (str) : a method's class name
            methodname (str) : a method's method name

        Returns:
            bool : True for exist one, False for none. 
        """
        method = self.find_method(classname=classname, methodname=methodname)
        return method != None
    
    def find_method(self, classname, methodname):
        """Find a method by its classname and methodname.

        Args:
            classname (str) : a method's class name
            methodname (str) : a method's method name

        Returns:
            generator<MethodClassAnalysis> : generator of found MethodClassAnalysis 
        """
        for cname, c in self.dx.classes.items():
            if classname == cname:
                for m in c.get_methods():
                    z = m.get_method()
                    if methodname == z.get_name():
                        return m
    
    def get_methodlist_cg(self, exist_list, outputchain=False):
        """get call graph from a list of methods.

        Args:
            exist_list (list) : a list of (classname, methodname)
            outputchain (bool) : if print chain
        
        Returns:
            DiGraph : call graph of the methods list
        """
        ancestors = set()
        for item_name in exist_list:
            m = self.find_method(classname=item_name[0], methodname=item_name[1])
            if m != None:
                print("found method: {} -- {}".format(item_name[0],item_name[1]))
                for _, call, _ in m.get_xref_from():
                    print("  called by -> {} -- {}".format(call.class_name, call.name))
                
                ancestors.update(nx.ancestors(self.CG, m.get_method()))
                ancestors.add(m.get_method())
        
        method_cg = self.CG.subgraph(ancestors)

        if outputchain:
            print("\n[*] finding existing call chain to method ...")
            chains = self.extract_chains(method_cg)
            self.show_chains(chains)

        return method_cg
    
    def extract_chains(self, G):
        """extract chains from a graph.

        Args:
            G (DiGraph) : a call graph
        
        Returns:
            iterator : iterator of chains
        """
        chaini = chain.from_iterable

        roots = (v for v, d in G.in_degree() if d == 0)
        leaves = (v for v, d in G.out_degree() if d == 0)
        all_paths = partial(nx.all_simple_paths, G)

        chains = chaini(starmap(all_paths, product(roots, leaves)))
        return chains
    
    def show_chains(self, chains):
        """print chains out

        Args:
            chains (iterator<chain>)
        """
        for chain in chains:
            for idx, m in enumerate(chain):
                if idx == 0:
                    print('   {} -- {}'.format(m.class_name, m.name))
                else:
                    print('-> {} -- {}'.format(m.class_name, m.name))
            print('')
    
    def extract_rootset(self, G):
        """extract a set of root from a call graph.

        Args:
            G (DiGraph) : a call graph
        
        Returns:
            set : a set of root classname
        """
        roots = (v for v, d in G.in_degree() if d == 0)
        root_set = set()
        #transform each class name into '*.*.*' form
        for root in roots:
            rcname = root.class_name
            if rcname not in root_set:
                root_set.add(rcname)
                print("  "+rcname)
        return root_set

    def check_class(self, rootclass, check_set, noact_set):
        """check if a class is activity/fragment.

        Args:
            rootclass (str) : root classname
            checkset (set) : if a class is activity then add in this set
            noact_set (set) : if a class is not activity then add in this set
        """
        #first check if L*/*/*; is exist
        #else check L*/*/*$*;
        root = rootclass.split(';',1)[0].split('$',1)[0]+';'
        itrclass = self.dx.get_class_analysis(root)
        is_activity = False
        if itrclass is not None:
            while(not itrclass.external):
                itrclass = self.dx.get_class_analysis(itrclass.extends)
                if( re.match('Landroid.*/app/(Activity|Fragment)', itrclass.name) ):
                    check_set.add(root)
                    return

        itrclass = self.dx.get_class_analysis(rootclass)
        while(not itrclass.external):
            itrclass = self.dx.get_class_analysis(itrclass.extends)
            if( re.match('Landroid.*/app/(Activity|Fragment)', itrclass.name) ):
                check_set.add(rootclass)
                is_activity = True
        if not is_activity:
            noact_set.add(rootclass)
    
    def check_noact_interface(self, start_cg, noact_set):
        """check if any interface of root in start_cg is activity.

        Args:
            start_cg (DiGraph) : a call graph
            noact_set (set) : no activity root classname to check
        
        Returns:
            set : a set of activity classname
        """
        print("\n[*] no root class is activity, search any activity calling interfaces of root class ...")
        #search any root class's interfaces
        start_cg_roots = [v for v, d in start_cg.in_degree() if d == 0]
        imps_set = set()
        check_set = set()
        for rootclass in noact_set:
            print("\nsearch any interfaces implemented by root class: {}".format(rootclass))
            root_imps = self.dx.classes[rootclass].implements
            if len(root_imps) != 0:
                for imp in root_imps:
                    if (imp != "Ljava/lang/Runnable;") and (imp not in imps_set):
                        print("\nfound interface: {}".format(imp))
                        imps_set.add(imp)
                        print("interface analysis:")
                        for methcls in start_cg_roots:
                            if methcls.class_name == rootclass:
                                imp_mname = methcls.name
                                if(not self.is_exist_meth(classname=imp, methodname=imp_mname)):
                                    print("\nnot found method in interface: {} -- {}".format(imp, imp_mname))
                                    continue

                                imp_cg = self.get_methodlist_cg([(imp, imp_mname)])

                                print("\nfinding this interface call chain root") 
                                imp_cg_rootset = self.extract_rootset(imp_cg)
                                tmp_act_set = set()
                                tmp_noact_set = set()
                                for rclass in imp_cg_rootset:
                                    self.check_class(rclass, tmp_act_set, tmp_noact_set)
                                
                                check_set.update(tmp_act_set)
        return check_set
    
    def get_close_interfaces(self, mclose):
        """extract methods in interface class that call close method.

        Args:
            mclose (MethodClassAnalysis) : close method
        
        Returns:
            set : a set of interface classname
        """
        close_ancestors = nx.ancestors(self.CG, mclose.get_method())
        close_ancestors.add(mclose.get_method())

        close_interfaces = set()
        for meth in close_ancestors:
            imps = self.dx.classes[meth.class_name].implements
            if len(imps) != 0:
                for imp in imps:
                    imp_meths = self.find_method(classname=imp, methodname=meth.name) # finding interface of ancestors
                    if imp_meths != None:
                        close_interfaces.add(imp_meths)
                        print("found cancel interface: {} -- {}".format(imp, meth.name))
        
        close_interfaces.add(mclose)
        return close_interfaces
    
    def reachable(self, msource, mtarget):
        """given source method and target method, if source method call target method

        Args:
            msource (MethodClassAnalysis) : source method
            mtarget (MethodClassAnalysis) : target method

        Returns:
            bool : if reachable from source method to target method in CG
        """
        descendants = nx.descendants(self.CG, msource.get_method())
        if mtarget.get_method() in descendants:
            print("close method can be found in activity: {}".format(msource.get_method().class_name))
            chains = nx.all_simple_paths(self.CG, source=msource.get_method(), target=mtarget.get_method())
            for chain in chains:
                for idx, m in enumerate(chain):
                    if idx == 0:
                        print('   {} -- {}'.format(m.class_name, m.name))
                    else:
                        print('-> {} -- {}'.format(m.class_name, m.name))
            print("***this activity is NOT vulnerable!!!***")
            return True
        else:
            return False
    
    def check_act_onPause_close(self, activity_name, close_set, event_meth='onPause'):
        """check if activity contain onPause and call methods in close_set
        
        Args:
            activity_name (str) : activity classname
            close_set (set) : a set of close methods
            event_meth (str) : the required event method
        
        Returns:
            bool : if close methods found in the required event method
        """
        itrclass = self.dx.classes[activity_name] 
        act_meths = [meth.name for meth in itrclass.get_methods()]
        while (event_meth not in act_meths):
            itrclass = self.dx.get_class_analysis(itrclass.extends)
            if itrclass.external:
                print("\n{} method NOT found in activity or its base class: {} : {}".format(event_meth, activity_name ,itrclass.name))
                print("***this activity is vulnearable!!!***")
                return False
            act_meths = [meth.name for meth in itrclass.get_methods()]

        pause_act_meths = {meth.name:meth for meth in itrclass.get_methods()}
        meth = pause_act_meths[event_meth]
        print("\n{} method found in activity or its base class: {} : {}".format(event_meth, activity_name, itrclass.name))
        print("inside method {}".format(meth.name))
        for _,call,_ in meth.get_xref_to():
            print("  calling -> {} -- {}".format(call.class_name, call.name))
        print("checking if {} call any close".format(event_meth))
        for mclose in close_set:
            if self.reachable(meth, mclose): 
                return True
        print("close method NOT found in activity or its base class: {} : {} -- {}".format(activity_name, meth.get_method().class_name, event_meth))
        print("***this activity is vulnerable!!!***")
        return False