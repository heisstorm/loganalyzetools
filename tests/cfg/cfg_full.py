if __name__ == '__main__':
    from staticfg import CFGBuilder

    cfg = CFGBuilder().build_from_file('quick sort', 'qsort.py')
    cfg.build_visual('qsort', 'png')